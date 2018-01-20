/*
 * Tegra host1x Channel
 *
 * Copyright (c) 2010-2013, NVIDIA Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/slab.h>
#include <linux/module.h>

#include "acm.h"
#include "channel.h"
#include "dev.h"
#include "job.h"

/* Constructor for the host1x device list */
int host1x_channel_list_init(struct host1x *host)
{
	INIT_LIST_HEAD(&host->chlist.list);
	mutex_init(&host->chlist_mutex);

	if (host->info->nb_channels > BITS_PER_LONG) {
		WARN(1, "host1x hardware has more channels than supported by the driver\n");
		return -ENOSYS;
	}

	return 0;
}

int host1x_job_submit(struct host1x_job *job)
{
	struct host1x *host = dev_get_drvdata(job->channel->dev->parent);
	int i;
	int err;

	for (i = 0; i < job->num_syncpts; i++)
		if (host->info->nb_pts <= job->syncpts[i].id)
			return -EINVAL;

	for (i = 0; i < job->num_syncpts; i++) {
		err = host1x_module_busy(job->channel->client);
		if (err < 0)
			goto error;
	}

	err = host1x_hw_channel_submit(host, job);
	if (err)
		goto error;

	return 0;

error:
	host1x_module_idle_mult(job->channel->client, i);
	return err;
}
EXPORT_SYMBOL(host1x_job_submit);

struct host1x_channel *host1x_channel_get(struct host1x_channel *channel,
					  struct host1x_user *user)
{
	int err = 0;

	mutex_lock(&channel->reflock);

	if (channel->refcount == 0) {
		err = host1x_cdma_init(&channel->cdma);
		if (err)
			goto done;
	}

	err = host1x_module_add_user(channel->client, user);
	if (err)
		goto err_cdma_deinit;

	channel->refcount++;

err_cdma_deinit:
	if (channel->refcount == 0)
		host1x_cdma_deinit(&channel->cdma);
done:
	mutex_unlock(&channel->reflock);
	return err ? NULL : channel;
}
EXPORT_SYMBOL(host1x_channel_get);

void host1x_channel_put(struct host1x_channel *channel,
			struct host1x_user *user)
{
	mutex_lock(&channel->reflock);

	host1x_module_remove_user(channel->client, user);

	if (channel->refcount == 1) {
		struct host1x *host = dev_get_drvdata(channel->dev->parent);

		host1x_hw_cdma_stop(host, &channel->cdma);
		host1x_cdma_deinit(&channel->cdma);
	}

	channel->refcount--;

	mutex_unlock(&channel->reflock);
}
EXPORT_SYMBOL(host1x_channel_put);

struct host1x_channel *host1x_channel_request(struct host1x_client *client)
{
	struct host1x *host = dev_get_drvdata(client->dev->parent);
	int max_channels = host->info->nb_channels;
	struct host1x_channel *channel = NULL;
	int index, err;

	mutex_lock(&host->chlist_mutex);

	index = find_first_zero_bit(&host->allocated_channels, max_channels);
	if (index >= max_channels)
		goto fail;

	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		goto fail;

	err = host1x_hw_channel_init(host, channel, index);
	if (err < 0)
		goto fail;

	/* Link device to host1x_channel */
	channel->dev = client->dev;

	/* Link host1x_client to host1x_channel */
	channel->client = client;

	/* Add to channel list */
	list_add_tail(&channel->list, &host->chlist.list);

	host->allocated_channels |= BIT(index);

	mutex_unlock(&host->chlist_mutex);
	return channel;

fail:
	dev_err(client->dev, "failed to init channel\n");
	kfree(channel);
	mutex_unlock(&host->chlist_mutex);
	return NULL;
}
EXPORT_SYMBOL(host1x_channel_request);

void host1x_channel_free(struct host1x_channel *channel)
{
	struct host1x *host = dev_get_drvdata(channel->dev->parent);

	host->allocated_channels &= ~BIT(channel->id);
	list_del(&channel->list);
	kfree(channel);
}
EXPORT_SYMBOL(host1x_channel_free);
