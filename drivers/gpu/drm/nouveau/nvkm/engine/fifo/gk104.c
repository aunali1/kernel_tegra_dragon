/*
 * Copyright 2012 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Ben Skeggs
 */
#include "gk104.h"

#include <core/client.h>
#include <core/engctx.h>
#include <core/enum.h>
#include <core/handle.h>
#include <subdev/bar.h>
#include <subdev/fb.h>
#include <subdev/mmu.h>
#include <subdev/pmu.h>
#include <subdev/timer.h>

#include <nvif/class.h>
#include <nvif/unpack.h>

#include "nouveau_drm.h"

/* engine status register has a field for context status */
#define CTXSW_STATUS_LOAD	5
#define CTXSW_STATUS_SAVE	6
#define CTXSW_STATUS_SWITCH	7

struct gk104_fifo_base {
	struct nvkm_fifo_base base;
	struct nvkm_gpuobj *pgd;
	struct nvkm_vm *vm;
};

struct gk104_fifo_chan {
	struct nvkm_fifo_chan base;
	u32 engine;
	enum {
		STOPPED,
		RUNNING,
		KILLED
	} state;
	struct {
		/* isr */
		u32 sum_ms;
		u32 limit_ms;
		u32 gpfifo_get;
		/* sw watchdog */
		bool watchdog_inited;
		struct delayed_work watchdog_work;
		u32 watchdog_gpfifo_get;
		spinlock_t watchdog_lock;
	} timeout;
};

#define GRFIFO_TIMEOUT_CHECK_PERIOD_MS	100
#define GRFIFO_TIMEOUT_DEFAULT		5000
#define GRFIFO_CHAN_WATCHDOG_TIMEOUT_MS	10000

static void
gk104_fifo_sched_ctxsw_recover(struct gk104_fifo_priv *priv,
		  struct nvkm_engine *engine, struct gk104_fifo_chan *chan);

static inline struct nvkm_engine *
gk104_fifo_engine(struct gk104_fifo_priv *priv, u32 engn);

/*******************************************************************************
 * FIFO channel objects
 ******************************************************************************/

static void
gk104_fifo_runlist_update(struct gk104_fifo_priv *priv, u32 engine)
{
	struct nvkm_bar *bar = nvkm_bar(priv);
	struct nvkm_pmu *pmu = nvkm_pmu(priv);
	struct gk104_fifo_engn *engn = &priv->engine[engine];
	struct nvkm_gpuobj *cur;
	int i, p;
	u32 token = 0;
	int mutex_ret;

	mutex_lock(&nv_subdev(priv)->mutex);

	mutex_ret = pmu->acquire_mutex(pmu, PMU_MUTEX_ID_FIFO, &token);
	if (mutex_ret)
		nv_error(priv, "runlist update acquire mutex failed: %d\n",
				mutex_ret);

	cur = engn->runlist[engn->cur_runlist];
	engn->cur_runlist = !engn->cur_runlist;

	for (i = 0, p = 0; i < priv->base.max; i++) {
		struct gk104_fifo_chan *chan = (void *)priv->base.channel[i];
		if (chan && chan->state == RUNNING && chan->engine == engine) {
			nv_wo32(cur, p + 0, i);
			nv_wo32(cur, p + 4, 0x00000000);
			p += 8;
		}
	}
	bar->flush(bar);

	nv_wr32(priv, 0x002270, cur->addr >> 12);
	nv_wr32(priv, 0x002274, (engine << 20) | (p >> 3));

	if (wait_event_timeout(engn->wait, !(nv_rd32(priv, 0x002284 +
			       (engine * 0x08)) & 0x00100000),
				msecs_to_jiffies(2000)) == 0)
		nv_error(priv, "runlist %d update timeout\n", engine);

	if (!mutex_ret)
		pmu->release_mutex(pmu, PMU_MUTEX_ID_FIFO, &token);

	mutex_unlock(&nv_subdev(priv)->mutex);
}

static void
gk104_fifo_chan_enable(struct nvkm_fifo_chan *chan, bool enable)
{
	struct nvkm_engine *engine = nv_object(chan)->engine;
	u32 state = enable ? 0x400 : 0x800;
	nv_mask(engine, 0x800004 + (chan->chid * 8), state, state);
}

static void
gk104_fifo_chan_timeout_start(struct nvkm_fifo_chan *chan)
{
	struct gk104_fifo_chan *ch = (void *)chan;
	unsigned long flags;

	spin_lock_irqsave(&ch->timeout.watchdog_lock, flags);
	if (ch->timeout.watchdog_inited) {
		spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);
		return;
	}

	ch->timeout.watchdog_gpfifo_get =
		nv_ro32(nv_object(chan)->parent, 0x20);
	ch->timeout.watchdog_inited = true;
	spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);

	schedule_delayed_work(&ch->timeout.watchdog_work,
			msecs_to_jiffies(GRFIFO_CHAN_WATCHDOG_TIMEOUT_MS));

	nv_debug(ch, "start channel %d watchdog\n", ch->base.chid);
}

static void
gk104_fifo_chan_timeout_stop(struct nvkm_fifo_chan *chan)
{
	struct gk104_fifo_chan *ch = (void *)chan;
	unsigned long flags;

	spin_lock_irqsave(&ch->timeout.watchdog_lock, flags);
	if (!ch->timeout.watchdog_inited) {
		spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);

	cancel_delayed_work(&ch->timeout.watchdog_work);

	spin_lock_irqsave(&ch->timeout.watchdog_lock, flags);
	ch->timeout.watchdog_inited = false;
	spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);

	nv_debug(ch, "stop channel %d watchdog\n", ch->base.chid);
}

static void
gk104_fifo_chan_timeout_work(struct work_struct *work)
{
	struct gk104_fifo_chan *ch;
	struct gk104_fifo_priv *priv;
	struct nvkm_object *object;
	struct device *dev;
	unsigned long flags;
	u32 chid;
	u32 pre, cur;
	int ret, quit = 0;

	ch = container_of(to_delayed_work(work), struct gk104_fifo_chan,
			timeout.watchdog_work);
	chid = ch->base.chid;
	object = (void *)ch;
	priv = (void *)object->engine;
	dev = nv_device_base(nv_device(priv));

	/* check timed out job */
	spin_lock_irqsave(&ch->timeout.watchdog_lock, flags);
	pre = ch->timeout.watchdog_gpfifo_get;
	if (!ch->timeout.watchdog_inited)
		quit = 1;
	ch->timeout.watchdog_inited = false;
	spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);

	if (quit)
		return;

	ret = pm_runtime_get_sync(dev);

	cur = nv_ro32(nv_object(ch)->parent, 0x20);
	if (cur != pre) {
		/* we have some progress, so re-start timer and keep monitoring */
		gk104_fifo_chan_timeout_start(&ch->base);
		goto skip_recovery;
	}

	/* the channel is stuck, so recover from that  */
	nv_error(ch, "Channel %d timed out\n", chid);

	nvkm_fifo_eevent(&priv->base, chid,
			NOUVEAU_GEM_CHANNEL_FIFO_ERROR_IDLE_TIMEOUT);
	gk104_fifo_sched_ctxsw_recover(priv, gk104_fifo_engine(priv, 0),
			ch);

skip_recovery:
	if (ret >= 0 || ret == -EACCES) {
		pm_runtime_mark_last_busy(dev);
		pm_runtime_put_autosuspend(dev);
	}
}

static bool
gk104_fifo_chan_timeout_restart_all(struct gk104_fifo_priv *priv,
		int exception)
{
	struct gk104_fifo_chan *ch;
	unsigned long flags;
	int i, ret;

	for (i = priv->base.min; i < priv->base.max; i++) {
		if (!(ch = (void *)priv->base.channel[i]))
			continue;

		spin_lock_irqsave(&ch->timeout.watchdog_lock, flags);
		if (!ch->timeout.watchdog_inited) {
			spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&ch->timeout.watchdog_lock, flags);

		ret = cancel_delayed_work(&ch->timeout.watchdog_work);
		if (!ret)
			return ret;

		/*
		 * We will handle timeout for this faulted channel , so no
		 * need to schedule another work.
		 */
		if (i == exception)
			continue;

		schedule_delayed_work(&ch->timeout.watchdog_work,
				msecs_to_jiffies(GRFIFO_CHAN_WATCHDOG_TIMEOUT_MS));
	}

	return true;
}

static int
gk104_fifo_context_attach(struct nvkm_object *parent,
			  struct nvkm_object *object)
{
	struct nvkm_bar *bar = nvkm_bar(parent);
	struct gk104_fifo_base *base = (void *)parent->parent;
	struct nvkm_engctx *ectx = (void *)object;
	u32 addr;
	int ret;

	switch (nv_engidx(object->engine)) {
	case NVDEV_ENGINE_SW   :
		return 0;
	case NVDEV_ENGINE_CE0:
	case NVDEV_ENGINE_CE1:
	case NVDEV_ENGINE_CE2:
		nv_engctx(ectx)->addr = nv_gpuobj(base)->addr >> 12;
		return 0;
	case NVDEV_ENGINE_GR    : addr = 0x0210; break;
	case NVDEV_ENGINE_MSVLD : addr = 0x0270; break;
	case NVDEV_ENGINE_MSPDEC: addr = 0x0250; break;
	case NVDEV_ENGINE_MSPPP : addr = 0x0260; break;
	default:
		return -EINVAL;
	}

	if (!ectx->vma.node) {
		ret = nvkm_gpuobj_map_vm(nv_gpuobj(ectx), base->vm,
					 NV_MEM_ACCESS_RW, &ectx->vma);
		if (ret)
			return ret;

		nv_engctx(ectx)->addr = nv_gpuobj(base)->addr >> 12;
	}

	nv_wo32(base, addr + 0x00, lower_32_bits(ectx->vma.offset) | 4);
	nv_wo32(base, addr + 0x04, upper_32_bits(ectx->vma.offset));
	bar->flush(bar);
	return 0;
}

static int
gk104_fifo_context_detach(struct nvkm_object *parent, bool suspend,
			  struct nvkm_object *object)
{
	struct nvkm_bar *bar = nvkm_bar(parent);
	struct gk104_fifo_base *base = (void *)parent->parent;
	struct gk104_fifo_chan *chan = (void *)parent;
	u32 addr;
	int err;

	switch (nv_engidx(object->engine)) {
	case NVDEV_ENGINE_SW    : return 0;
	case NVDEV_ENGINE_CE0   :
	case NVDEV_ENGINE_CE1   :
	case NVDEV_ENGINE_CE2   : addr = 0x0000; break;
	case NVDEV_ENGINE_GR    : addr = 0x0210; break;
	case NVDEV_ENGINE_MSVLD : addr = 0x0270; break;
	case NVDEV_ENGINE_MSPDEC: addr = 0x0250; break;
	case NVDEV_ENGINE_MSPPP : addr = 0x0260; break;
	default:
		return -EINVAL;
	}

	err = gf100_fifo_chan_kick_locked(&chan->base);
	if (err && suspend)
		return err;

	if (addr) {
		nv_wo32(base, addr + 0x00, 0x00000000);
		nv_wo32(base, addr + 0x04, 0x00000000);
		bar->flush(bar);
	}

	return 0;
}

static int
gk104_fifo_chan_ctor(struct nvkm_object *parent, struct nvkm_object *engine,
		     struct nvkm_oclass *oclass, void *data, u32 size,
		     struct nvkm_object **pobject)
{
	union {
		struct kepler_channel_gpfifo_a_v0 v0;
	} *args = data;
	struct nvkm_bar *bar = nvkm_bar(parent);
	struct gk104_fifo_priv *priv = (void *)engine;
	struct gk104_fifo_base *base = (void *)parent;
	struct gk104_fifo_impl *impl = (void *)nv_oclass(priv);
	struct gk104_fifo_chan *chan;
	u64 usermem, ioffset, ilength;
	int ret, i;

	nv_ioctl(parent, "create channel gpfifo size %d\n", size);
	if (nvif_unpack(args->v0, 0, 0, false)) {
		nv_ioctl(parent, "create channel gpfifo vers %d pushbuf %08x "
				 "ioffset %016llx ilength %08x engine %08x\n",
			 args->v0.version, args->v0.pushbuf, args->v0.ioffset,
			 args->v0.ilength, args->v0.engine);
	} else
		return ret;

	for (i = 0; i < impl->num_engine; i++) {
		if (args->v0.engine & (1 << i)) {
			if (nvkm_engine(parent, impl->engine[i].subdev)) {
				args->v0.engine = (1 << i);
				break;
			}
		}
	}

	if (i == impl->num_engine) {
		nv_error(priv, "unsupported engines 0x%08x\n", args->v0.engine);
		return -ENODEV;
	}

	ret = nvkm_fifo_channel_create(parent, engine, oclass, 1,
				       priv->user.bar.offset, 0x200,
				       args->v0.pushbuf,
				       impl->engine[i].mask, &chan);
	*pobject = nv_object(chan);
	if (ret)
		return ret;

	args->v0.chid = chan->base.chid;

	nv_parent(chan)->context_attach = gk104_fifo_context_attach;
	nv_parent(chan)->context_detach = gk104_fifo_context_detach;
	chan->engine = i;

	usermem = chan->base.chid * 0x200;
	ioffset = args->v0.ioffset;
	ilength = order_base_2(args->v0.ilength / 8);

	for (i = 0; i < 0x200; i += 4)
		nv_wo32(priv->user.mem, usermem + i, 0x00000000);

	nv_wo32(base, 0x08, lower_32_bits(priv->user.mem->addr + usermem));
	nv_wo32(base, 0x0c, upper_32_bits(priv->user.mem->addr + usermem));
	nv_wo32(base, 0x10, 0x0000face);
	nv_wo32(base, 0x30, 0xfffff902);
	nv_wo32(base, 0x48, lower_32_bits(ioffset));
	nv_wo32(base, 0x4c, upper_32_bits(ioffset) | (ilength << 16));
	nv_wo32(base, 0x84, 0x20400000);
	nv_wo32(base, 0x94, 0x30000001);
	nv_wo32(base, 0x9c, 0x00000100);
	nv_wo32(base, 0xac, 0x0000001f);
	nv_wo32(base, 0xe8, chan->base.chid);
	nv_wo32(base, 0xb8, 0xf8000000);
	nv_wo32(base, 0xf8, 0x10003080); /* 0x002310 */
	nv_wo32(base, 0xfc, 0x10000010); /* 0x002350 */
	bar->flush(bar);

	chan->timeout.sum_ms = 0;
	chan->timeout.limit_ms = GRFIFO_TIMEOUT_DEFAULT;
	chan->timeout.gpfifo_get = 0;
	spin_lock_init(&chan->timeout.watchdog_lock);
	INIT_DELAYED_WORK(&chan->timeout.watchdog_work,
			gk104_fifo_chan_timeout_work);
	chan->base.timeout_start = gk104_fifo_chan_timeout_start;
	chan->base.timeout_stop = gk104_fifo_chan_timeout_stop;

	return 0;
}

static int
gk104_fifo_chan_init(struct nvkm_object *object)
{
	struct nvkm_gpuobj *base = nv_gpuobj(object->parent);
	struct gk104_fifo_priv *priv = (void *)object->engine;
	struct gk104_fifo_chan *chan = (void *)object;
	u32 chid = chan->base.chid;
	int ret;

	ret = nvkm_fifo_channel_init(&chan->base);
	if (ret)
		return ret;

	nv_mask(priv, 0x800004 + (chid * 8), 0x000f0000, chan->engine << 16);
	nv_wr32(priv, 0x800000 + (chid * 8), 0x80000000 | base->addr >> 12);

	if (chan->state == STOPPED && (chan->state = RUNNING) == RUNNING) {
		nvkm_fifo_chan_enable(&priv->base, &chan->base);
		gk104_fifo_runlist_update(priv, chan->engine);
		nvkm_fifo_chan_enable(&priv->base, &chan->base);
	}

	return 0;
}

static int
gk104_fifo_chan_fini(struct nvkm_object *object, bool suspend)
{
	struct gk104_fifo_priv *priv = (void *)object->engine;
	struct gk104_fifo_chan *chan = (void *)object;
	u32 chid = chan->base.chid;
	int err;

	if (suspend &&
		!nv_wait(priv, 0x002640 + chan->engine * 8, 0x80000000,
			0x00000000)) {
		nv_error(priv, "fifo engine %d wait idle timeout\n",
				chan->engine);
		return -ETIMEDOUT;
	}

	gk104_fifo_chan_timeout_stop(&chan->base);

	if (chan->state == RUNNING && (chan->state = STOPPED) == STOPPED) {
		nvkm_fifo_chan_disable(&priv->base, &chan->base);
		gk104_fifo_runlist_update(priv, chan->engine);
	}

	err = gf100_fifo_chan_kick(&chan->base);
	if (err && suspend)
		return err;

	nv_wr32(priv, 0x800000 + (chid * 8), 0x00000000);
	return nvkm_fifo_channel_fini(&chan->base, suspend);
}

static void
gk104_fifo_set_runlist_timeslice(struct gk104_fifo_priv *priv,
		struct gk104_fifo_chan *chan, u8 slice)
{
	struct nvkm_gpuobj *base = nv_gpuobj(nv_object(chan)->parent);
	u32 chid = chan->base.chid;

	nvkm_fifo_chan_disable(&priv->base, &chan->base);
	WARN_ON(gf100_fifo_chan_kick(&chan->base));
	nv_wo32(base, 0xf8, slice | 0x10003000);
	nvkm_fifo_chan_enable(&priv->base, &chan->base);
	nv_debug(chan, "timeslice set to %d for %d\n", slice, chid);
}

static int
gk104_fifo_chan_set_priority(struct nvkm_object *object, void *data, u32 size)
{
	struct gk104_fifo_priv *priv = (void *)object->engine;
	struct gk104_fifo_chan *chan = (void *)object;
	union {
		struct kepler_set_channel_priority_v0 v0;
	} *args = data;
	int ret;
	u8 slice;

	if (nvif_unpack(args->v0, 0, 0, false)) {
		switch (args->v0.priority) {
		case KEPLER_SET_CHANNEL_PRIORITY_LOW:
			slice = 64; /* << 3 == 512 us */
			break;
		case KEPLER_SET_CHANNEL_PRIORITY_MEDIUM:
			slice = 128; /* 1 ms */
			break;
		case KEPLER_SET_CHANNEL_PRIORITY_HIGH:
			slice = 255; /* 2 ms */
			break;
		default:
			return -EINVAL;
		}
		gk104_fifo_set_runlist_timeslice(priv, chan, slice);
		return 0;
	}

	return ret;
}

static int
gk104_fifo_chan_set_timeout(struct nvkm_object *object, void *data, u32 size)
{
	struct gk104_fifo_chan *chan = (void *)object;
	union {
		struct kepler_set_channel_timeout_v0 v0;
	} *args = data;
	int ret;

	if (nvif_unpack(args->v0, 0, 0, false)) {
		chan->timeout.limit_ms = args->v0.timeout_ms;
		nv_debug(chan, "timeout set to %d ms for %d\n",
				args->v0.timeout_ms, chan->base.chid);
	}

	return ret;
}

static int
gk104_fifo_chan_mthd(struct nvkm_object *object, u32 mthd, void *data, u32 size)
{
	switch (mthd) {
	case KEPLER_SET_CHANNEL_PRIORITY:
		return gk104_fifo_chan_set_priority(object, data, size);
	case KEPLER_SET_CHANNEL_TIMEOUT:
		return gk104_fifo_chan_set_timeout(object, data, size);
	default:
		break;
	}
	return -EINVAL;
}

struct nvkm_ofuncs
gk104_fifo_chan_ofuncs = {
	.ctor = gk104_fifo_chan_ctor,
	.dtor = _nvkm_fifo_channel_dtor,
	.init = gk104_fifo_chan_init,
	.fini = gk104_fifo_chan_fini,
	.mthd = gk104_fifo_chan_mthd,
	.map  = _nvkm_fifo_channel_map,
	.rd32 = _nvkm_fifo_channel_rd32,
	.wr32 = _nvkm_fifo_channel_wr32,
	.ntfy = _nvkm_fifo_channel_ntfy
};

static struct nvkm_oclass
gk104_fifo_sclass[] = {
	{ KEPLER_CHANNEL_GPFIFO_A, &gk104_fifo_chan_ofuncs },
	{}
};

/*******************************************************************************
 * FIFO context - instmem heap and vm setup
 ******************************************************************************/

static int
gk104_fifo_context_ctor(struct nvkm_object *parent, struct nvkm_object *engine,
			struct nvkm_oclass *oclass, void *data, u32 size,
			struct nvkm_object **pobject)
{
	struct gk104_fifo_base *base;
	struct nvkm_mmu *mmu = nvkm_mmu(parent);
	u64 length = (0x1ULL << mmu->dma_bits) - 1;
	int ret;

	/* allocate instance block */
	ret = nvkm_fifo_context_create(parent, engine, oclass, NULL, 0x1000,
				       0x1000, NVOBJ_FLAG_ZERO_ALLOC, &base);
	if (ret)
		return ret;

	/* allocate and initialize pgd */
	ret = mmu->create_pgd(mmu, nv_object(base), base, length, &base->pgd);
	if (ret)
		goto err_pgd;

	ret = nvkm_vm_ref(nvkm_client(parent)->vm, &base->vm, base->pgd);
	if (ret)
		goto err_ref;

	*pobject = nv_object(base);
	return 0;

err_ref:
	nvkm_gpuobj_destroy(base->pgd);
err_pgd:
	nvkm_fifo_context_destroy(&base->base);
	return ret;
}

static void
gk104_fifo_context_dtor(struct nvkm_object *object)
{
	struct gk104_fifo_base *base = (void *)object;
	nvkm_vm_ref(NULL, &base->vm, base->pgd);
	nvkm_gpuobj_ref(NULL, &base->pgd);
	nvkm_fifo_context_destroy(&base->base);
}

static struct nvkm_oclass
gk104_fifo_cclass = {
	.handle = NV_ENGCTX(FIFO, 0xe0),
	.ofuncs = &(struct nvkm_ofuncs) {
		.ctor = gk104_fifo_context_ctor,
		.dtor = gk104_fifo_context_dtor,
		.init = _nvkm_fifo_context_init,
		.fini = _nvkm_fifo_context_fini,
		.rd32 = _nvkm_fifo_context_rd32,
		.wr32 = _nvkm_fifo_context_wr32,
	},
};

/*******************************************************************************
 * PFIFO engine
 ******************************************************************************/

static inline int
gk104_fifo_engidx(struct gk104_fifo_priv *priv, u32 engn)
{
	switch (engn) {
	case NVDEV_ENGINE_GR    :
	case NVDEV_ENGINE_CE2   : engn = 0; break;
	case NVDEV_ENGINE_MSVLD : engn = 1; break;
	case NVDEV_ENGINE_MSPPP : engn = 2; break;
	case NVDEV_ENGINE_MSPDEC: engn = 3; break;
	case NVDEV_ENGINE_CE0   : engn = 4; break;
	case NVDEV_ENGINE_CE1   : engn = 5; break;
	case NVDEV_ENGINE_MSENC : engn = 6; break;
	default:
		return -1;
	}

	return engn;
}

static inline struct nvkm_engine *
gk104_fifo_engine(struct gk104_fifo_priv *priv, u32 engn)
{
	struct gk104_fifo_impl *impl = (void *)nv_oclass(priv);
	if (engn >= impl->num_engine)
		return NULL;
	return nvkm_engine(priv, impl->engine[engn].subdev);
}

static void
gk104_fifo_mmu_fault_recover_work(struct work_struct *work)
{
	struct gk104_fifo_priv *priv = container_of(work, typeof(*priv), mmu_fault);
	struct gk104_fifo_chan *chan;
	struct device *dev = nv_device_base(nv_device(priv));
	struct nvkm_pmu *pmu = nvkm_pmu(priv);
	struct nvkm_gr *gr = nvkm_gr(priv);
	struct nvkm_object *engine;
	unsigned long flags;
	u32 engn, engm = 0, unit;
	u64 mask, todo;
	bool halt_fecs = false;
	u32 grfifo_ctrl;
	int ret;

	ret = pm_runtime_get_sync(dev);

	spin_lock_irqsave(&priv->base.lock, flags);
	mask = priv->mask;
	chan = priv->fault_chan;
	unit = priv->fault_unit;
	priv->mask = 0ULL;
	priv->fault_chan = NULL;
	priv->fault_unit = 0;
	spin_unlock_irqrestore(&priv->base.lock, flags);

	if (pmu->disable_clk_gating)
		pmu->disable_clk_gating(pmu);

	for (todo = mask; engn = __ffs64(todo), todo; todo &= ~(1 << engn)) {
		engm |= 1 << gk104_fifo_engidx(priv, engn);
		if (engn == NVDEV_ENGINE_GR)
			halt_fecs = true;
	}

	nv_debug(priv, "disabling scheduling runlist 0x%08x\n", engm);
	nv_mask(priv, 0x002630, engm, engm);
	if (halt_fecs && gr->halt_fecs)
		gr->halt_fecs(gr);

	for (todo = mask; engn = __ffs64(todo), todo; todo &= ~(1 << engn)) {
		if ((engine = (void *)nvkm_engine(priv, engn))) {
			nv_error(priv, "resetting engine 0x%x\n", engn);
			nv_ofuncs(engine)->fini(engine, false);
			WARN_ON(nv_ofuncs(engine)->init(engine));
		}
	}

	grfifo_ctrl = nv_rd32(priv, 0x400500);
	grfifo_ctrl |= 0x1 << 16; /* semaphore access */
	grfifo_ctrl |= 0x1 << 0; /* access */
	nv_wr32(priv, 0x400500, grfifo_ctrl);

	nv_debug(priv, "updating runlist\n");
	for (todo = mask; engn = __ffs64(todo), todo; todo &= ~(1 << engn)) {
		gk104_fifo_runlist_update(priv, gk104_fifo_engidx(priv, engn));
	}

	nv_wr32(priv, 0x00259c, unit);
	nv_wr32(priv, 0x00262c, engm);
	nv_mask(priv, 0x002630, engm, 0x00000000);
	nv_mask(priv, 0x002140, 0x10000100, 0x10000100);

	if (pmu->enable_clk_gating)
		pmu->enable_clk_gating(pmu);

	nv_error(priv, "channel clean up done\n");

	if (ret >= 0 || ret == -EACCES) {
		pm_runtime_mark_last_busy(dev);
		pm_runtime_put_autosuspend(dev);
	}
}

static void
gk104_fifo_mmu_fault_recover(struct gk104_fifo_priv *priv,
		struct nvkm_engine *engine, struct gk104_fifo_chan *chan,
		u32 unit)
{
	u32 chid = chan->base.chid;
	unsigned long flags;
	u32 grfifo_ctrl;

	nv_error(priv, "%s engine mmu fault on channel %d\n",
		       nv_subdev(engine)->name, chid);

	grfifo_ctrl = nv_rd32(priv, 0x400500);
	grfifo_ctrl &= ~(0x1 << 16); /* semaphore access */
	grfifo_ctrl &= ~(0x1 << 0); /* access */
	nv_wr32(priv, 0x400500, grfifo_ctrl);

	nvkm_fifo_chan_disable(&priv->base, &chan->base);
	chan->state = KILLED;

	spin_lock_irqsave(&priv->base.lock, flags);
	priv->mask |= 1ULL << nv_engidx(engine);
	priv->fault_chan = chan;
	priv->fault_unit |= 1 << unit;
	spin_unlock_irqrestore(&priv->base.lock, flags);

	/* Notify upper layer to signal pending fences */
	nvkm_fifo_uevent_fault(&priv->base, chid);

	/* Do the real recovery work */
	queue_work(system_highpri_wq, &priv->mmu_fault);
}

static void
gk104_fifo_sched_ctxsw_recover(struct gk104_fifo_priv *priv,
		  struct nvkm_engine *engine, struct gk104_fifo_chan *chan)
{
	u32 chid = chan->base.chid;

	nv_error(priv, "%s engine sched ctxsw timeout on channel %d\n",
		       nv_subdev(engine)->name, chid);

	/* disable interrupt */
	nv_mask(priv, 0x002140, 0x10000100, 0x00000000);
	nv_wr32(priv, 0x002100, 0x00000100);
	/* trigger mmu fault */
	nv_wr32(priv, 0x002a30, 0x00000100);
	if (!nv_wait(priv, 0x002100, 0x10000000, 0x10000000))
		nv_error(priv, "triggering mmu fault timed out\n");
	nv_wr32(priv, 0x002a30, 0x00000000);

	/* handle fake mmu fault */
	gk104_fifo_mmu_fault_recover(priv, engine, chan, 0);
}

static int
gk104_fifo_swmthd(struct gk104_fifo_priv *priv, u32 chid, u32 mthd, u32 data)
{
	struct gk104_fifo_chan *chan = NULL;
	struct nvkm_handle *bind;
	unsigned long flags;
	int ret = -EINVAL;

	spin_lock_irqsave(&priv->base.lock, flags);
	if (likely(chid >= priv->base.min && chid <= priv->base.max))
		chan = (void *)priv->base.channel[chid];
	if (unlikely(!chan))
		goto out;

	bind = nvkm_namedb_get_class(nv_namedb(chan), 0x906e);
	if (likely(bind)) {
		if (!mthd || !nv_call(bind->object, mthd, data))
			ret = 0;
		nvkm_namedb_put(bind);
	}

out:
	spin_unlock_irqrestore(&priv->base.lock, flags);
	return ret;
}

static const struct nvkm_enum
gk104_fifo_bind_reason[] = {
	{ 0x01, "BIND_NOT_UNBOUND" },
	{ 0x02, "SNOOP_WITHOUT_BAR1" },
	{ 0x03, "UNBIND_WHILE_RUNNING" },
	{ 0x05, "INVALID_RUNLIST" },
	{ 0x06, "INVALID_CTX_TGT" },
	{ 0x0b, "UNBIND_WHILE_PARKED" },
	{}
};

static void
gk104_fifo_intr_bind(struct gk104_fifo_priv *priv)
{
	u32 intr = nv_rd32(priv, 0x00252c);
	u32 code = intr & 0x000000ff;
	const struct nvkm_enum *en;
	char enunk[6] = "";

	en = nvkm_enum_find(gk104_fifo_bind_reason, code);
	if (!en)
		snprintf(enunk, sizeof(enunk), "UNK%02x", code);

	nv_error(priv, "BIND_ERROR [ %s ]\n", en ? en->name : enunk);
}

static const struct nvkm_enum
gk104_fifo_sched_reason[] = {
	{ 0x0a, "CTXSW_TIMEOUT" },
	{}
};

static bool
gk104_fifo_update_timeout(struct gk104_fifo_priv *priv,
		struct gk104_fifo_chan *chan, u32 dt)
{
	u32 gpfifo_get = nv_ro32(nv_object(chan)->parent, 0x20);

	/* advancing, but slowly; reset counting */
	if (gpfifo_get != chan->timeout.gpfifo_get)
		chan->timeout.sum_ms = 0;

	chan->timeout.sum_ms += dt;
	chan->timeout.gpfifo_get = gpfifo_get;

	return chan->timeout.sum_ms > chan->timeout.limit_ms;
}

static void
_update_recovery_delay(struct gk104_fifo_priv *priv)
{
	struct device *dev = nv_device_base(nv_device(priv));
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct nouveau_drm *drm = nouveau_drm(drm_dev);

	pm_runtime_mark_last_busy(dev);
	drm->recovery_delay = jiffies + 10 * HZ;
}

static void
gk104_fifo_intr_sched_ctxsw(struct gk104_fifo_priv *priv)
{
	struct nvkm_engine *engine;
	struct gk104_fifo_chan *chan;
	struct gk104_fifo_impl *impl = (void *)nv_oclass(priv);
	u32 engn;

	for (engn = 0; engn < impl->num_engine; engn++) {
		u32 stat = nv_rd32(priv, 0x002640 + (engn * 0x08));
		u32 busy = (stat & 0x80000000);
		u32 next = (stat & 0x0fff0000) >> 16;
		u32 ctxstat = (stat & 0x0000e000) >> 13;
		u32 prev = (stat & 0x00000fff);

		u32 chid = (ctxstat == CTXSW_STATUS_LOAD) ? next : prev;
		u32 ctxsw_active = ctxstat == CTXSW_STATUS_LOAD ||
			ctxstat == CTXSW_STATUS_SAVE ||
			ctxstat == CTXSW_STATUS_SWITCH;

		if (busy && ctxsw_active) {
			if (!(chan = (void *)priv->base.channel[chid]))
				continue;
			if (!(engine = gk104_fifo_engine(priv, engn)))
				continue;

			if (gk104_fifo_update_timeout(priv, chan,
						GRFIFO_TIMEOUT_CHECK_PERIOD_MS)) {
				nvkm_fifo_eevent(&priv->base, chid,
						NOUVEAU_GEM_CHANNEL_FIFO_ERROR_IDLE_TIMEOUT);
				if (gk104_fifo_chan_timeout_restart_all(priv, chid)) {
					nv_error(priv, "recovering ctxsw timeout for ch %d\n",
							chid);
					gk104_fifo_sched_ctxsw_recover(priv, engine, chan);
				}
			} else {
				_update_recovery_delay(priv);
				nv_error(priv, "fifo waiting for ctxsw %d ms on ch %d\n",
						chan->timeout.sum_ms, chid);
			}
		}
	}
}

static void
gk104_fifo_intr_sched(struct gk104_fifo_priv *priv)
{
	u32 intr = nv_rd32(priv, 0x00254c);
	u32 code = intr & 0x000000ff;
	const struct nvkm_enum *en;
	char enunk[6] = "";

	en = nvkm_enum_find(gk104_fifo_sched_reason, code);
	if (!en)
		snprintf(enunk, sizeof(enunk), "UNK%02x", code);

	switch (code) {
	case 0x0a:
		gk104_fifo_intr_sched_ctxsw(priv);
		break;
	default:
		nv_error(priv, "SCHED_ERROR [ %s ]\n", en ? en->name : enunk);
		break;
	}
}

static void
gk104_fifo_intr_chsw(struct gk104_fifo_priv *priv)
{
	u32 stat = nv_rd32(priv, 0x00256c);
	nv_error(priv, "CHSW_ERROR 0x%08x\n", stat);
	nv_wr32(priv, 0x00256c, stat);
}

static void
gk104_fifo_intr_dropped_fault(struct gk104_fifo_priv *priv)
{
	u32 stat = nv_rd32(priv, 0x00259c);
	nv_error(priv, "DROPPED_MMU_FAULT 0x%08x\n", stat);
}

static const struct nvkm_enum
gk104_fifo_fault_engine[] = {
	{ 0x00, "GR", NULL, NVDEV_ENGINE_GR },
	{ 0x03, "IFB", NULL, NVDEV_ENGINE_IFB },
	{ 0x04, "BAR1", NULL, NVDEV_SUBDEV_BAR },
	{ 0x05, "BAR3", NULL, NVDEV_SUBDEV_INSTMEM },
	{ 0x07, "PBDMA0", NULL, NVDEV_ENGINE_FIFO },
	{ 0x08, "PBDMA1", NULL, NVDEV_ENGINE_FIFO },
	{ 0x09, "PBDMA2", NULL, NVDEV_ENGINE_FIFO },
	{ 0x10, "MSVLD", NULL, NVDEV_ENGINE_MSVLD },
	{ 0x11, "MSPPP", NULL, NVDEV_ENGINE_MSPPP },
	{ 0x13, "PERF" },
	{ 0x14, "MSPDEC", NULL, NVDEV_ENGINE_MSPDEC },
	{ 0x15, "CE0", NULL, NVDEV_ENGINE_CE0 },
	{ 0x16, "CE1", NULL, NVDEV_ENGINE_CE1 },
	{ 0x17, "PMU" },
	{ 0x19, "MSENC", NULL, NVDEV_ENGINE_MSENC },
	{ 0x1b, "CE2", NULL, NVDEV_ENGINE_CE2 },
	{}
};

static const struct nvkm_enum
gk104_fifo_fault_reason[] = {
	{ 0x00, "PDE" },
	{ 0x01, "PDE_SIZE" },
	{ 0x02, "PTE" },
	{ 0x03, "VA_LIMIT_VIOLATION" },
	{ 0x04, "UNBOUND_INST_BLOCK" },
	{ 0x05, "PRIV_VIOLATION" },
	{ 0x06, "RO_VIOLATION" },
	{ 0x07, "WO_VIOLATION" },
	{ 0x08, "PITCH_MASK_VIOLATION" },
	{ 0x09, "WORK_CREATION" },
	{ 0x0a, "UNSUPPORTED_APERTURE" },
	{ 0x0b, "COMPRESSION_FAILURE" },
	{ 0x0c, "UNSUPPORTED_KIND" },
	{ 0x0d, "REGION_VIOLATION" },
	{ 0x0e, "BOTH_PTES_VALID" },
	{ 0x0f, "INFO_TYPE_POISONED" },
	{}
};

static const struct nvkm_enum
gk104_fifo_fault_hubclient[] = {
	{ 0x00, "VIP" },
	{ 0x01, "CE0" },
	{ 0x02, "CE1" },
	{ 0x03, "DNISO" },
	{ 0x04, "FE" },
	{ 0x05, "FECS" },
	{ 0x06, "HOST" },
	{ 0x07, "HOST_CPU" },
	{ 0x08, "HOST_CPU_NB" },
	{ 0x09, "ISO" },
	{ 0x0a, "MMU" },
	{ 0x0b, "MSPDEC" },
	{ 0x0c, "MSPPP" },
	{ 0x0d, "MSVLD" },
	{ 0x0e, "NISO" },
	{ 0x0f, "P2P" },
	{ 0x10, "PD" },
	{ 0x11, "PERF" },
	{ 0x12, "PMU" },
	{ 0x13, "RASTERTWOD" },
	{ 0x14, "SCC" },
	{ 0x15, "SCC_NB" },
	{ 0x16, "SEC" },
	{ 0x17, "SSYNC" },
	{ 0x18, "GR_CE" },
	{ 0x19, "CE2" },
	{ 0x1a, "XV" },
	{ 0x1b, "MMU_NB" },
	{ 0x1c, "MSENC" },
	{ 0x1d, "DFALCON" },
	{ 0x1e, "SKED" },
	{ 0x1f, "AFALCON" },
	{}
};

static const struct nvkm_enum
gk104_fifo_fault_gpcclient[] = {
	{ 0x00, "L1_0" }, { 0x01, "T1_0" }, { 0x02, "PE_0" },
	{ 0x03, "L1_1" }, { 0x04, "T1_1" }, { 0x05, "PE_1" },
	{ 0x06, "L1_2" }, { 0x07, "T1_2" }, { 0x08, "PE_2" },
	{ 0x09, "L1_3" }, { 0x0a, "T1_3" }, { 0x0b, "PE_3" },
	{ 0x0c, "RAST" },
	{ 0x0d, "GCC" },
	{ 0x0e, "GPCCS" },
	{ 0x0f, "PROP_0" },
	{ 0x10, "PROP_1" },
	{ 0x11, "PROP_2" },
	{ 0x12, "PROP_3" },
	{ 0x13, "L1_4" }, { 0x14, "T1_4" }, { 0x15, "PE_4" },
	{ 0x16, "L1_5" }, { 0x17, "T1_5" }, { 0x18, "PE_5" },
	{ 0x19, "L1_6" }, { 0x1a, "T1_6" }, { 0x1b, "PE_6" },
	{ 0x1c, "L1_7" }, { 0x1d, "T1_7" }, { 0x1e, "PE_7" },
	{ 0x1f, "GPM" },
	{ 0x20, "LTP_UTLB_0" },
	{ 0x21, "LTP_UTLB_1" },
	{ 0x22, "LTP_UTLB_2" },
	{ 0x23, "LTP_UTLB_3" },
	{ 0x24, "GPC_RGG_UTLB" },
	{}
};

static void
gk104_fifo_intr_fault(struct gk104_fifo_priv *priv, int unit)
{
	u32 inst = nv_rd32(priv, 0x002800 + (unit * 0x10));
	u32 valo = nv_rd32(priv, 0x002804 + (unit * 0x10));
	u32 vahi = nv_rd32(priv, 0x002808 + (unit * 0x10));
	u32 stat = nv_rd32(priv, 0x00280c + (unit * 0x10));
	u32 gpc    = (stat & 0x1f000000) >> 24;
	u32 client = (stat & 0x00001f00) >> 8;
	u32 write  = (stat & 0x00000080);
	u32 hub    = (stat & 0x00000040);
	u32 reason = (stat & 0x0000000f);
	struct nvkm_object *engctx = NULL, *object;
	struct nvkm_engine *engine = NULL;
	const struct nvkm_enum *er, *eu, *ec;
	char erunk[6] = "";
	char euunk[6] = "";
	char ecunk[6] = "";
	char gpcid[3] = "";

	nv_error(priv, "faulting unit is %d\n", unit);

	er = nvkm_enum_find(gk104_fifo_fault_reason, reason);
	if (!er)
		snprintf(erunk, sizeof(erunk), "UNK%02X", reason);

	eu = nvkm_enum_find(gk104_fifo_fault_engine, unit);
	if (eu) {
		switch (eu->data2) {
		case NVDEV_SUBDEV_BAR:
			nv_mask(priv, 0x001704, 0x00000000, 0x00000000);
			break;
		case NVDEV_SUBDEV_INSTMEM:
			nv_mask(priv, 0x001714, 0x00000000, 0x00000000);
			break;
		case NVDEV_ENGINE_IFB:
			nv_mask(priv, 0x001718, 0x00000000, 0x00000000);
			break;
		default:
			engine = nvkm_engine(priv, eu->data2);
			if (engine)
				engctx = nvkm_engctx_get(engine, inst);
			break;
		}
	} else {
		snprintf(euunk, sizeof(euunk), "UNK%02x", unit);
	}

	if (hub) {
		ec = nvkm_enum_find(gk104_fifo_fault_hubclient, client);
	} else {
		ec = nvkm_enum_find(gk104_fifo_fault_gpcclient, client);
		snprintf(gpcid, sizeof(gpcid), "%d", gpc);
	}

	if (!ec)
		snprintf(ecunk, sizeof(ecunk), "UNK%02x", client);

	nv_error(priv, "%s fault at 0x%010llx [%s] from %s/%s%s%s%s on "
		       "channel 0x%010llx [%s]\n", write ? "write" : "read",
		 (u64)vahi << 32 | valo, er ? er->name : erunk,
		 eu ? eu->name : euunk, hub ? "" : "GPC", gpcid, hub ? "" : "/",
		 ec ? ec->name : ecunk, (u64)inst << 12,
		 nvkm_client_name(engctx));

	object = engctx;
	while (object) {
		switch (nv_mclass(object)) {
		case KEPLER_CHANNEL_GPFIFO_A:
		case MAXWELL_CHANNEL_GPFIFO_A:
			nvkm_fifo_eevent(&priv->base,
					((struct nvkm_fifo_chan*)object)->chid,
					NOUVEAU_GEM_CHANNEL_FIFO_ERROR_MMU_ERR_FLT);
			_update_recovery_delay(priv);
			gk104_fifo_mmu_fault_recover(priv, engine, (void *)object, unit);
			break;
		}
		object = object->parent;
	}

	nvkm_engctx_put(engctx);
}

static const struct nvkm_bitfield gk104_fifo_pbdma_intr_0[] = {
	{ 0x00000001, "MEMREQ" },
	{ 0x00000002, "MEMACK_TIMEOUT" },
	{ 0x00000004, "MEMACK_EXTRA" },
	{ 0x00000008, "MEMDAT_TIMEOUT" },
	{ 0x00000010, "MEMDAT_EXTRA" },
	{ 0x00000020, "MEMFLUSH" },
	{ 0x00000040, "MEMOP" },
	{ 0x00000080, "LBCONNECT" },
	{ 0x00000100, "LBREQ" },
	{ 0x00000200, "LBACK_TIMEOUT" },
	{ 0x00000400, "LBACK_EXTRA" },
	{ 0x00000800, "LBDAT_TIMEOUT" },
	{ 0x00001000, "LBDAT_EXTRA" },
	{ 0x00002000, "GPFIFO" },
	{ 0x00004000, "GPPTR" },
	{ 0x00008000, "GPENTRY" },
	{ 0x00010000, "GPCRC" },
	{ 0x00020000, "PBPTR" },
	{ 0x00040000, "PBENTRY" },
	{ 0x00080000, "PBCRC" },
	{ 0x00100000, "XBARCONNECT" },
	{ 0x00200000, "METHOD" },
	{ 0x00400000, "METHODCRC" },
	{ 0x00800000, "DEVICE" },
	{ 0x02000000, "SEMAPHORE" },
	{ 0x04000000, "ACQUIRE" },
	{ 0x08000000, "PRI" },
	{ 0x20000000, "NO_CTXSW_SEG" },
	{ 0x40000000, "PBSEG" },
	{ 0x80000000, "SIGNATURE" },
	{}
};

static void
gk104_fifo_intr_pbdma_0(struct gk104_fifo_priv *priv, int unit)
{
	u32 mask = nv_rd32(priv, 0x04010c + (unit * 0x2000));
	u32 stat = nv_rd32(priv, 0x040108 + (unit * 0x2000)) & mask;
	u32 addr = nv_rd32(priv, 0x0400c0 + (unit * 0x2000));
	u32 data = nv_rd32(priv, 0x0400c4 + (unit * 0x2000));
	u32 chid = nv_rd32(priv, 0x040120 + (unit * 0x2000)) & 0xfff;
	u32 subc = (addr & 0x00070000) >> 16;
	u32 mthd = (addr & 0x00003ffc);
	u32 show = stat;

	if (stat & 0x00800000) {
		if (!gk104_fifo_swmthd(priv, chid, mthd, data))
			show &= ~0x00800000;
		nv_wr32(priv, 0x0400c0 + (unit * 0x2000), 0x80600008);
	}

	if (stat & 0x00200000)
		nv_wr32(priv, 0x0400c0 + (unit * 0x2000), 0x00000008);

	if (show) {
		static unsigned long int j;
		if (printk_timed_ratelimit(&j, 1000)) {
			nv_error(priv, "PBDMA%d:", unit);
			nvkm_bitfield_print(gk104_fifo_pbdma_intr_0, show);
			pr_cont("\n");
			nv_error(priv,
				 "PBDMA%d: ch %d [%s] subc %d mthd 0x%04x data 0x%08x\n",
				 unit, chid,
				 nvkm_client_name_for_fifo_chid(&priv->base, chid),
				 subc, mthd, data);
		}
		nvkm_fifo_eevent(&priv->base, chid,
				NOUVEAU_GEM_CHANNEL_PBDMA_ERROR);
	}

	nv_wr32(priv, 0x040108 + (unit * 0x2000), stat);
}

static const struct nvkm_bitfield gk104_fifo_pbdma_intr_1[] = {
	{ 0x00000001, "HCE_RE_ILLEGAL_OP" },
	{ 0x00000002, "HCE_RE_ALIGNB" },
	{ 0x00000004, "HCE_PRIV" },
	{ 0x00000008, "HCE_ILLEGAL_MTHD" },
	{ 0x00000010, "HCE_ILLEGAL_CLASS" },
	{}
};

static void
gk104_fifo_intr_pbdma_1(struct gk104_fifo_priv *priv, int unit)
{
	u32 mask = nv_rd32(priv, 0x04014c + (unit * 0x2000));
	u32 stat = nv_rd32(priv, 0x040148 + (unit * 0x2000)) & mask;
	u32 chid = nv_rd32(priv, 0x040120 + (unit * 0x2000)) & 0xfff;

	if (stat) {
		nv_error(priv, "PBDMA%d:", unit);
		nvkm_bitfield_print(gk104_fifo_pbdma_intr_1, stat);
		pr_cont("\n");
		nv_error(priv, "PBDMA%d: ch %d %08x %08x\n", unit, chid,
			 nv_rd32(priv, 0x040150 + (unit * 0x2000)),
			 nv_rd32(priv, 0x040154 + (unit * 0x2000)));
		nvkm_fifo_eevent(&priv->base, chid,
				NOUVEAU_GEM_CHANNEL_PBDMA_ERROR);
	}

	nv_wr32(priv, 0x040148 + (unit * 0x2000), stat);
}

static void
gk104_fifo_intr_runlist(struct gk104_fifo_priv *priv)
{
	u32 mask = nv_rd32(priv, 0x002a00);
	while (mask) {
		u32 engn = __ffs(mask);
		wake_up(&priv->engine[engn].wait);
		nv_wr32(priv, 0x002a00, 1 << engn);
		mask &= ~(1 << engn);
	}
}

static void
gk104_fifo_intr_engine(struct gk104_fifo_priv *priv)
{
	nvkm_fifo_uevent(&priv->base);
}

static void
gk104_fifo_intr(struct nvkm_subdev *subdev)
{
	struct gk104_fifo_priv *priv = (void *)subdev;
	u32 mask = nv_rd32(priv, 0x002140);
	u32 stat = nv_rd32(priv, 0x002100) & mask;

	if (stat & 0x00000001) {
		gk104_fifo_intr_bind(priv);
		nv_wr32(priv, 0x002100, 0x00000001);
		stat &= ~0x00000001;
	}

	if (stat & 0x00000010) {
		nv_error(priv, "PIO_ERROR\n");
		nv_wr32(priv, 0x002100, 0x00000010);
		stat &= ~0x00000010;
	}

	if (stat & 0x00000100) {
		gk104_fifo_intr_sched(priv);
		nv_wr32(priv, 0x002100, 0x00000100);
		stat &= ~0x00000100;
	}

	if (stat & 0x00010000) {
		gk104_fifo_intr_chsw(priv);
		nv_wr32(priv, 0x002100, 0x00010000);
		stat &= ~0x00010000;
	}

	if (stat & 0x00800000) {
		nv_error(priv, "FB_FLUSH_TIMEOUT\n");
		nv_wr32(priv, 0x002100, 0x00800000);
		stat &= ~0x00800000;
	}

	if (stat & 0x01000000) {
		nv_error(priv, "LB_ERROR\n");
		nv_wr32(priv, 0x002100, 0x01000000);
		stat &= ~0x01000000;
	}

	if (stat & 0x08000000) {
		gk104_fifo_intr_dropped_fault(priv);
		nv_wr32(priv, 0x002100, 0x08000000);
		stat &= ~0x08000000;
	}

	if (stat & 0x10000000) {
		u32 mask = nv_rd32(priv, 0x00259c);
		nv_mask(priv, 0x002140, 0x10000000, 0x00000000);
		while (mask) {
			u32 unit = __ffs(mask);
			gk104_fifo_intr_fault(priv, unit);
			mask &= ~(1 << unit);
		}
		stat &= ~0x10000000;
	}

	if (stat & 0x20000000) {
		u32 mask = nv_rd32(priv, 0x0025a0);
		while (mask) {
			u32 unit = __ffs(mask);
			gk104_fifo_intr_pbdma_0(priv, unit);
			gk104_fifo_intr_pbdma_1(priv, unit);
			nv_wr32(priv, 0x0025a0, (1 << unit));
			mask &= ~(1 << unit);
		}
		stat &= ~0x20000000;
	}

	if (stat & 0x40000000) {
		gk104_fifo_intr_runlist(priv);
		stat &= ~0x40000000;
	}

	if (stat & 0x80000000) {
		nv_wr32(priv, 0x002100, 0x80000000);
		gk104_fifo_intr_engine(priv);
		stat &= ~0x80000000;
	}

	if (stat) {
		nv_error(priv, "INTR 0x%08x\n", stat);
		nv_mask(priv, 0x002140, stat, 0x00000000);
		nv_wr32(priv, 0x002100, stat);
	}
}

static void
gk104_fifo_uevent_init(struct nvkm_event *event, int type, int index)
{
	struct nvkm_fifo *fifo = container_of(event, typeof(*fifo), uevent);
	nv_mask(fifo, 0x002140, 0x80000000, 0x80000000);
}

static void
gk104_fifo_uevent_fini(struct nvkm_event *event, int type, int index)
{
	struct nvkm_fifo *fifo = container_of(event, typeof(*fifo), uevent);
	nv_mask(fifo, 0x002140, 0x80000000, 0x00000000);
}

static const struct nvkm_event_func
gk104_fifo_uevent_func = {
	.ctor = nvkm_fifo_uevent_ctor,
	.init = gk104_fifo_uevent_init,
	.fini = gk104_fifo_uevent_fini,
};

int
gk104_fifo_fini(struct nvkm_object *object, bool suspend)
{
	struct gk104_fifo_priv *priv = (void *)object;
	int ret;

	flush_work(&priv->mmu_fault);

	ret = nvkm_fifo_fini(&priv->base, suspend);
	if (ret)
		return ret;

	/* allow mmu fault interrupts, even when we're not using fifo */
	nv_mask(priv, 0x002140, 0x10000000, 0x10000000);
	return 0;
}

int
gk104_fifo_init(struct nvkm_object *object)
{
	struct gk104_fifo_priv *priv = (void *)object;
	int ret, i;

	ret = nvkm_fifo_init(&priv->base);
	if (ret)
		return ret;

	/* enable all available PBDMA units */
	nv_wr32(priv, 0x000204, 0xffffffff);
	priv->spoon_nr = hweight32(nv_rd32(priv, 0x000204));
	nv_debug(priv, "%d PBDMA unit(s)\n", priv->spoon_nr);

	/* PBDMA[n] */
	for (i = 0; i < priv->spoon_nr; i++) {
		nv_mask(priv, 0x04013c + (i * 0x2000), 0x10000100, 0x00000000);
		nv_wr32(priv, 0x040108 + (i * 0x2000), 0xffffffff); /* INTR */
		nv_wr32(priv, 0x04010c + (i * 0x2000), 0xfffffeff); /* INTREN */
	}

	/* PBDMA[n].HCE */
	for (i = 0; i < priv->spoon_nr; i++) {
		nv_wr32(priv, 0x040148 + (i * 0x2000), 0xffffffff); /* INTR */
		nv_wr32(priv, 0x04014c + (i * 0x2000), 0xffffffff); /* INTREN */
	}

	nv_wr32(priv, 0x002254, 0x10000000 | priv->user.bar.offset >> 12);

	/* enable interrupts */
	nv_wr32(priv, 0x002100, 0xffffffff);
	nv_wr32(priv, 0x002140, 0x7fffffff);

	/* engine context switch timeout */
	nv_wr32(priv, 0x002a0c, 0x80000000 | (1000 * GRFIFO_TIMEOUT_CHECK_PERIOD_MS));
	return 0;
}

void
gk104_fifo_dtor(struct nvkm_object *object)
{
	struct gk104_fifo_priv *priv = (void *)object;
	struct gk104_fifo_impl *impl = (void *)nv_oclass(priv);
	int i;

	flush_work(&priv->mmu_fault);

	nvkm_gpuobj_unmap(&priv->user.bar);
	nvkm_gpuobj_ref(NULL, &priv->user.mem);

	for (i = 0; i < impl->num_engine; i++) {
		nvkm_gpuobj_ref(NULL, &priv->engine[i].runlist[1]);
		nvkm_gpuobj_ref(NULL, &priv->engine[i].runlist[0]);
	}

	kfree(priv->engine);

	nvkm_fifo_destroy(&priv->base);
}

int
gk104_fifo_ctor(struct nvkm_object *parent, struct nvkm_object *engine,
		struct nvkm_oclass *oclass, void *data, u32 size,
		struct nvkm_object **pobject)
{
	struct gk104_fifo_impl *impl = (void *)oclass;
	struct gk104_fifo_priv *priv;
	int ret, i;

	ret = nvkm_fifo_create(parent, engine, oclass, 0,
			       impl->channels - 1, &priv);
	*pobject = nv_object(priv);
	if (ret)
		return ret;

	INIT_WORK(&priv->mmu_fault, gk104_fifo_mmu_fault_recover_work);

	priv->engine = kzalloc(impl->num_engine * sizeof(priv->engine[0]),
			GFP_KERNEL);
	if (!priv->engine)
		return -ENOMEM;

	for (i = 0; i < impl->num_engine; i++) {
		ret = nvkm_gpuobj_new(nv_object(priv), NULL, 0x8000, 0x1000,
				      0, &priv->engine[i].runlist[0]);
		if (ret)
			return ret;

		ret = nvkm_gpuobj_new(nv_object(priv), NULL, 0x8000, 0x1000,
				      0, &priv->engine[i].runlist[1]);
		if (ret)
			return ret;

		init_waitqueue_head(&priv->engine[i].wait);
	}

	ret = nvkm_gpuobj_new(nv_object(priv), NULL, impl->channels * 0x200,
			      0x1000, NVOBJ_FLAG_ZERO_ALLOC, &priv->user.mem);
	if (ret)
		return ret;

	ret = nvkm_gpuobj_map(priv->user.mem, NV_MEM_ACCESS_RW,
			      &priv->user.bar);
	if (ret)
		return ret;

	ret = nvkm_event_init(&gk104_fifo_uevent_func, 1, 1, &priv->base.uevent);
	if (ret)
		return ret;

	nv_subdev(priv)->unit = 0x00000100;
	nv_subdev(priv)->intr = gk104_fifo_intr;
	nv_engine(priv)->cclass = &gk104_fifo_cclass;
	nv_engine(priv)->sclass = gk104_fifo_sclass;

	priv->base.enable = gk104_fifo_chan_enable;

	return 0;
}

struct nvkm_oclass *
gk104_fifo_oclass = &(struct gk104_fifo_impl) {
	.base.handle = NV_ENGINE(FIFO, 0xe0),
	.base.ofuncs = &(struct nvkm_ofuncs) {
		.ctor = gk104_fifo_ctor,
		.dtor = gk104_fifo_dtor,
		.init = gk104_fifo_init,
		.fini = gk104_fifo_fini,
	},
	.channels = 4096,
	.engine = gk104_fifo_engines,
	.num_engine = ARRAY_SIZE(gk104_fifo_engines),
}.base;
