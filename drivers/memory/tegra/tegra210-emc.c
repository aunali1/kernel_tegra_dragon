/*
 * Copyright (c) 2015, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/kernel.h>
#include <linux/clk-provider.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/thermal.h>

#include <soc/tegra/tegra_emc.h>
#include <soc/tegra/fuse.h>

#include "tegra210-emc-reg.h"

#define TEGRA_EMC_TABLE_MAX_SIZE		16
#define EMC_STATUS_UPDATE_TIMEOUT		1000
#define TEGRA210_SAVE_RESTORE_MOD_REGS		12
#define TEGRA_EMC_DEFAULT_CLK_LATENCY_US	2000

static bool emc_enable = true;
module_param(emc_enable, bool, 0644);

enum TEGRA_EMC_SOURCE {
	TEGRA_EMC_SRC_PLLM,
	TEGRA_EMC_SRC_PLLC,
	TEGRA_EMC_SRC_PLLP,
	TEGRA_EMC_SRC_CLKM,
	TEGRA_EMC_SRC_PLLM_UD,
	TEGRA_EMC_SRC_PLLMB_UD,
	TEGRA_EMC_SRC_PLLMB,
	TEGRA_EMC_SRC_PLLP_UD,
	TEGRA_EMC_SRC_COUNT,
};

struct emc_sel {
	struct clk	*input;
	u32		value;
	unsigned long	input_rate;

	struct clk	*input_b;
	u32		value_b;
	unsigned long	input_rate_b;
};

#define DEFINE_REG(type, reg) (reg)
u32 burst_regs_per_ch_off[] = BURST_REGS_PER_CH_LIST;
u32 burst_regs_off[] = BURST_REGS_LIST;
u32 trim_regs_per_ch_off[] = TRIM_REGS_PER_CH_LIST;
u32 trim_regs_off[] = TRIM_REGS_LIST;
u32 burst_mc_regs_off[] = BURST_MC_REGS_LIST;
u32 la_scale_regs_off[] = BURST_UP_DOWN_REGS_LIST;
u32 vref_regs_per_ch_off[] = VREF_REGS_PER_CH_LIST;
#undef DEFINE_REG

#define DEFINE_REG(type, reg) (type)
u32 burst_regs_per_ch_type[] = BURST_REGS_PER_CH_LIST;
u32 trim_regs_per_ch_type[] = TRIM_REGS_PER_CH_LIST;
u32 vref_regs_per_ch_type[] = VREF_REGS_PER_CH_LIST;
#undef DEFINE_REG

static struct supported_sequence *seq;
static DEFINE_SPINLOCK(emc_access_lock);
static ktime_t clkchange_time;
int tegra_emc_table_size;
static int clkchange_delay = 100;
static int last_round_idx;
static int last_rate_idx;
static u32 tegra_dram_dev_num;
static u32 tegra_dram_type = -1;
static u32 tegra_ram_code;
static u32 current_clksrc;
static u32 timer_period_training = 100;
static bool tegra_emc_init_done;
static void __iomem *emc_base;
static void __iomem *emc0_base;
static void __iomem *emc1_base;
static void __iomem *mc_base;
void __iomem *clk_base;
static unsigned long emc_max_rate;
static unsigned long emc_override_rate;
unsigned long dram_over_temp_state = TEGRA_DRAM_OVER_TEMP_NONE;
static struct emc_stats tegra_emc_stats;
struct emc_table *tegra_emc_table;
struct emc_table *tegra_emc_table_normal;
struct emc_table *tegra_emc_table_derated;
static struct emc_table *emc_timing;
static struct emc_table start_timing;
static struct emc_sel *emc_clk_sel;
static struct clk *emc_clk;
static struct clk *emc_override_clk;
static struct clk *tegra_emc_src[TEGRA_EMC_SRC_COUNT];
static const char *tegra_emc_src_names[TEGRA_EMC_SRC_COUNT] = {
	[TEGRA_EMC_SRC_PLLM] = "pll_m",
	[TEGRA_EMC_SRC_PLLC] = "pll_c",
	[TEGRA_EMC_SRC_PLLP] = "pll_p",
	[TEGRA_EMC_SRC_CLKM] = "clk_m",
	[TEGRA_EMC_SRC_PLLM_UD] = "pll_m",
	[TEGRA_EMC_SRC_PLLMB_UD] = "pll_mb",
	[TEGRA_EMC_SRC_PLLMB] = "pll_mb",
	[TEGRA_EMC_SRC_PLLP_UD] = "pll_p",
};
static struct supported_sequence supported_seqs[] = {
	{
		0x6,
		emc_set_clock_r21015,
		__do_periodic_emc_compensation_r21015,
		"21018"
	},
	{
		0,
		NULL,
		NULL,
		NULL
	}
};

static void emc_train(unsigned long nothing);
static struct timer_list emc_timer_training =
	TIMER_INITIALIZER(emc_train, 0, 0);

static u8 tegra210_emc_bw_efficiency = 80;
static u8 tegra210_emc_iso_share = 100;
static unsigned long last_iso_bw;

static u32 bw_calc_freqs[] = {
	5, 10, 20, 30, 40, 60, 80, 100, 120, 140, 160, 180,
	200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700
};

static u32 tegra210_lpddr3_iso_efficiency_os_idle[] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 63, 60, 54, 45, 45, 45, 45, 45, 45, 45
};
static u32 tegra210_lpddr3_iso_efficiency_general[] = {
	60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
	60, 59, 59, 58, 57, 56, 55, 54, 54, 54, 54
};

static u32 tegra210_lpddr4_iso_efficiency_os_idle[] = {
	56, 56, 56, 56, 56, 56, 56, 56, 56, 56, 56, 56,
	56, 56, 56, 56, 56, 56, 56, 56, 56, 49, 45
};
static u32 tegra210_lpddr4_iso_efficiency_general[] = {
	56, 55, 55, 54, 54, 53, 51, 50, 49, 48, 47, 46,
	45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45
};

static u32 tegra210_ddr3_iso_efficiency_os_idle[] = {
	65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
	65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65
};
static u32 tegra210_ddr3_iso_efficiency_general[] = {
	60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
	60, 59, 59, 58, 57, 56, 55, 54, 54, 54, 54
};

static u8 iso_share_calc_tegra210_os_idle(unsigned long iso_bw);
static u8 iso_share_calc_tegra210_general(unsigned long iso_bw);

static struct emc_iso_usage tegra210_emc_iso_usage[] = {
	{
		BIT(EMC_USER_DC1),
		80, iso_share_calc_tegra210_os_idle
	},
	{
		BIT(EMC_USER_DC2),
		80, iso_share_calc_tegra210_os_idle
	},
	{
		BIT(EMC_USER_DC1) | BIT(EMC_USER_DC2),
		50, iso_share_calc_tegra210_general
	},
	{
		BIT(EMC_USER_DC1) | BIT(EMC_USER_VI),
		50, iso_share_calc_tegra210_general
	},
	{
		BIT(EMC_USER_DC1) | BIT(EMC_USER_DC2) | BIT(EMC_USER_VI),
		50, iso_share_calc_tegra210_general
	},
};

inline void emc_writel(u32 val, unsigned long offset)
{
	writel(val, emc_base + offset);
}

inline u32 emc_readl(unsigned long offset)
{
	return readl(emc_base + offset);
}

inline void emc1_writel(u32 val, unsigned long offset)
{
	writel(val, emc1_base + offset);
}

inline u32 emc1_readl(unsigned long offset)
{
	return readl(emc1_base + offset);
}

inline void emc_writel_per_ch(u32 val, int type, unsigned long offset)
{
	switch (type) {
	case REG_EMC:
	case REG_EMC0:
		return writel(val, emc_base + offset);
	case REG_EMC1:
		return writel(val, emc1_base + offset);
	}
}

inline u32 emc_readl_per_ch(int type, unsigned long offset)
{
	u32 val;
	switch (type) {
	case REG_EMC:
	case REG_EMC0:
		val = readl(emc_base + offset);
		break;
	case REG_EMC1:
		val = readl(emc1_base + offset);
		break;
	}
	return val;
}

inline void mc_writel(u32 val, unsigned long offset)
{
	writel(val, mc_base + offset);
}

inline u32 mc_readl(unsigned long offset)
{
	return readl(mc_base + offset);
}

static inline int get_start_idx(unsigned long rate)
{
	if (tegra_emc_table[last_round_idx].rate == rate)
		return last_round_idx;
	return 0;
}

static inline u32 emc_src_val(u32 val)
{
	return (val & EMC_CLK_EMC_2X_CLK_SRC_MASK) >>
		EMC_CLK_EMC_2X_CLK_SRC_SHIFT;
}

static inline u32 emc_div_val(u32 val)
{
	return (val & EMC_CLK_EMC_2X_CLK_DIVISOR_MASK) >>
		EMC_CLK_EMC_2X_CLK_DIVISOR_SHIFT;
}

inline void ccfifo_writel(u32 val, unsigned long addr, u32 delay)
{
	writel(val, emc_base + EMC_CCFIFO_DATA);
	writel((addr & 0xffff) | ((delay & 0x7fff) << 16) | (1 << 31),
		emc_base + EMC_CCFIFO_ADDR);
}

static void emc_train(unsigned long nothing)
{
	unsigned long flags;

	if (!emc_timing)
		return;

	spin_lock_irqsave(&emc_access_lock, flags);
	if (seq->periodic_compensation)
		seq->periodic_compensation(emc_timing);
	spin_unlock_irqrestore(&emc_access_lock, flags);

	mod_timer(&emc_timer_training,
		  jiffies + msecs_to_jiffies(timer_period_training));
}

static void emc_timer_training_start(void)
{
	mod_timer(&emc_timer_training,
		  jiffies + msecs_to_jiffies(timer_period_training));
}

static void emc_timer_training_stop(void)
{
	del_timer(&emc_timer_training);
}

struct emc_table *get_timing_from_freq(unsigned long rate)
{
	int i;

	for (i = 0; i < tegra_emc_table_size; i++)
		if (tegra_emc_table[i].rate == rate)
			return &tegra_emc_table[i];

	return NULL;
}

int wait_for_update(u32 status_reg, u32 bit_mask, bool updated_state, int chan)
{
	int i, err = -ETIMEDOUT;
	u32 reg;

	for (i = 0; i < EMC_STATUS_UPDATE_TIMEOUT; i++) {
		reg = emc_readl_per_ch(chan, status_reg);
		if (!!(reg & bit_mask) == updated_state) {
			err = 0;
			goto done;
		}
		udelay(1);
	}

done:
	return err;
}

void do_clock_change(u32 clk_setting)
{
	int err;

	mc_readl(MC_EMEM_ADR_CFG);
	emc_readl(EMC_INTSTATUS);

	writel(clk_setting, clk_base + CLK_RST_CONTROLLER_CLK_SOURCE_EMC);
	readl(clk_base + CLK_RST_CONTROLLER_CLK_SOURCE_EMC);

	err = wait_for_update(EMC_INTSTATUS, EMC_INTSTATUS_CLKCHANGE_COMPLETE,
			      true, REG_EMC);
	if (err) {
		pr_err("%s: clock change completion error: %d", __func__, err);
		BUG();
	}
}

void emc_set_shadow_bypass(int set)
{
	u32 emc_dbg = emc_readl(EMC_DBG);

	if (set)
		emc_writel(emc_dbg | EMC_DBG_WRITE_MUX_ACTIVE, EMC_DBG);
	else
		emc_writel(emc_dbg & ~EMC_DBG_WRITE_MUX_ACTIVE, EMC_DBG);
}

u32 get_dll_state(struct emc_table *next_timing)
{
	bool next_dll_enabled;

	next_dll_enabled = !(next_timing->emc_emrs & 0x1);
	if (next_dll_enabled)
		return DLL_ON;
	else
		return DLL_OFF;
}

u32 div_o3(u32 a, u32 b)
{
	u32 result = a / b;

	if ((b * result) < a)
		return result + 1;
	else
		return result;
}

void emc_timing_update(int dual_chan)
{
	int err = 0;

	emc_writel(0x1, EMC_TIMING_CONTROL);
	err |= wait_for_update(EMC_EMC_STATUS,
			       EMC_EMC_STATUS_TIMING_UPDATE_STALLED, false,
			       REG_EMC);
	if (dual_chan)
		err |= wait_for_update(EMC_EMC_STATUS,
				       EMC_EMC_STATUS_TIMING_UPDATE_STALLED,
				       false, REG_EMC1);
	if (err) {
		pr_err("%s: timing update error: %d", __func__, err);
		BUG();
	}
}

void tegra210_emc_timing_invalidate(void)
{
	emc_timing = NULL;
}
EXPORT_SYMBOL(tegra210_emc_timing_invalidate);

bool tegra210_emc_is_ready(void)
{
	return tegra_emc_init_done;
}
EXPORT_SYMBOL(tegra210_emc_is_ready);

unsigned long tegra210_predict_emc_rate(int millivolts)
{
	int i;
	unsigned long ret = 0;

	if (!emc_enable)
		return -ENODEV;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return -EINVAL;

	for (i = 0; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;
		if (tegra_emc_table[i].min_volt > millivolts)
			break;
		ret = tegra_emc_table[i].rate * 1000;
	}

	return ret;
}
EXPORT_SYMBOL(tegra210_predict_emc_rate);

static unsigned long tegra210_emc_get_rate(void)
{
	u32 val;
	u32 div_value;
	u32 src_value;
	unsigned long rate;

	if (!emc_enable)
		return -ENODEV;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return -EINVAL;

	val = readl(clk_base + CLK_RST_CONTROLLER_CLK_SOURCE_EMC);

	div_value = emc_div_val(val);
	src_value = emc_src_val(val);

	rate = __clk_get_rate(tegra_emc_src[src_value]);

	do_div(rate, div_value + 2);

	return rate * 2;
}

static long tegra210_emc_round_rate(unsigned long rate)
{
	int i;
	int max = 0;

	if (!emc_enable)
		return 0;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return 0;

	rate /= 1000;
	i = get_start_idx(rate);
	for (; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;

		max = i;
		if (tegra_emc_table[i].rate >= rate) {
			last_round_idx = i;
			return tegra_emc_table[i].rate * 1000;
		}
	}

	return tegra_emc_table[max].rate * 1000;
}

unsigned int tegra210_emc_get_clk_latency(unsigned long rate)
{
	int i, index;

	if (!emc_enable || !tegra_emc_init_done || !tegra_emc_table_size)
		return TEGRA_EMC_DEFAULT_CLK_LATENCY_US;

	rate /= 1000;
	for (i = 0; i < tegra_emc_table_size; i++) {
		if (tegra_emc_table[i].rate > rate)
			break;

		index = i;
	}

	if (tegra_emc_table[index].latency)
		return tegra_emc_table[index].latency;

	return TEGRA_EMC_DEFAULT_CLK_LATENCY_US;
}
EXPORT_SYMBOL(tegra210_emc_get_clk_latency);

static inline void emc_get_timing(struct emc_table *timing)
{
	int i;

	for (i = 0; i < timing->num_burst; i++) {
		if (burst_regs_off[i])
			timing->burst_regs[i] = emc_readl(burst_regs_off[i]);
		else
			timing->burst_regs[i] = 0;
	}

	for (i = 0; i < timing->num_burst_per_ch; i++)
		timing->burst_reg_per_ch[i] = emc_readl_per_ch(
			burst_regs_per_ch_type[i], burst_regs_per_ch_off[i]);

	for (i = 0; i < timing->num_trim; i++)
		timing->trim_regs[i] = emc_readl(trim_regs_off[i]);

	for (i = 0; i < timing->num_trim_per_ch; i++)
		timing->trim_perch_regs[i] = emc_readl_per_ch(
			trim_regs_per_ch_type[i], trim_regs_per_ch_off[i]);

	for (i = 0; i < timing->vref_num; i++)
		timing->vref_perch_regs[i] = emc_readl_per_ch(
			vref_regs_per_ch_type[i], vref_regs_per_ch_off[i]);

	for (i = 0; i < timing->num_mc_regs; i++)
		timing->burst_mc_regs[i] = mc_readl(burst_mc_regs_off[i]);

	for (i = 0; i < timing->num_up_down; i++)
		timing->la_scale_regs[i] = mc_readl(la_scale_regs_off[i]);

	timing->rate = clk_get_rate(emc_clk) / 1000;
}

static void emc_set_clock(struct emc_table *next_timing,
		struct emc_table *last_timing, int training, u32 clksrc)
{
	current_clksrc = clksrc;
	seq->set_clock(next_timing, last_timing, training, clksrc);

	if (next_timing->periodic_training)
		emc_timer_training_start();
	else
		emc_timer_training_stop();
}

static void emc_last_stats_update(int last_sel)
{
	unsigned long flags;
	u64 cur_jiffies = get_jiffies_64();

	spin_lock_irqsave(&tegra_emc_stats.spinlock, flags);

	if (tegra_emc_stats.last_sel < TEGRA_EMC_TABLE_MAX_SIZE)
		tegra_emc_stats.time_at_clock[tegra_emc_stats.last_sel] =
			tegra_emc_stats.time_at_clock[tegra_emc_stats.last_sel]
			+ (cur_jiffies - tegra_emc_stats.last_update);

	tegra_emc_stats.last_update = cur_jiffies;

	if (last_sel < TEGRA_EMC_TABLE_MAX_SIZE) {
		tegra_emc_stats.clkchange_count++;
		tegra_emc_stats.last_sel = last_sel;
	}
	spin_unlock_irqrestore(&tegra_emc_stats.spinlock, flags);
}

static int emc_table_lookup(unsigned long rate)
{
	int i;
	i = get_start_idx(rate);
	for (; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;

		if (tegra_emc_table[i].rate == rate)
			break;
	}

	if (i >= tegra_emc_table_size)
		return -EINVAL;
	return i;
}

static struct clk *tegra210_emc_predict_parent(unsigned long rate,
						unsigned long *parent_rate)
{
	int val;
	struct clk *old_parent, *new_parent;

	if (!tegra_emc_table)
		return ERR_PTR(-EINVAL);

	val = emc_table_lookup(rate / 1000);
	if (IS_ERR_VALUE(val))
		return ERR_PTR(val);

	*parent_rate = emc_clk_sel[val].input_rate * 1000;
	new_parent = emc_clk_sel[val].input;
	old_parent = clk_get_parent(emc_clk);

	if (*parent_rate == clk_get_rate(old_parent))
		return old_parent;

	if (new_parent == old_parent)
		new_parent = emc_clk_sel[val].input_b;

	if (*parent_rate != clk_get_rate(new_parent))
		clk_set_rate(new_parent, *parent_rate);

	return new_parent;
}

static int tegra210_emc_set_rate(unsigned long rate)
{
	int i;
	u32 clk_setting;
	struct emc_table *last_timing;
	unsigned long flags;
	s64 last_change_delay;
	struct clk *parent;
	unsigned long parent_rate;

	if (!emc_enable)
		return -ENODEV;

	if (!tegra_emc_init_done || !tegra_emc_table_size)
		return -EINVAL;

	if (rate == tegra210_emc_get_rate())
		return 0;

	i = emc_table_lookup(rate / 1000);

	if (IS_ERR_VALUE(i))
		return i;

	if (rate > 204000000 && !tegra_emc_table[i].trained)
		return -EINVAL;

	if (!emc_timing) {
		emc_get_timing(&start_timing);
		last_timing = &start_timing;
	} else
		last_timing = emc_timing;

	parent = tegra210_emc_predict_parent(rate, &parent_rate);
	if (parent == emc_clk_sel[i].input)
		clk_setting = emc_clk_sel[i].value;
	else
		clk_setting = emc_clk_sel[i].value_b;

	last_change_delay = ktime_us_delta(ktime_get(), clkchange_time);
	if ((last_change_delay >= 0) && (last_change_delay < clkchange_delay))
		udelay(clkchange_delay - (int)last_change_delay);

	spin_lock_irqsave(&emc_access_lock, flags);
	emc_set_clock(&tegra_emc_table[i], last_timing, 0, clk_setting);
	clkchange_time = ktime_get();
	emc_timing = &tegra_emc_table[i];
	last_rate_idx = i;
	spin_unlock_irqrestore(&emc_access_lock, flags);

	emc_last_stats_update(i);

	return 0;
}

static inline int bw_calc_get_freq_idx(unsigned long bw)
{
	int max_idx = ARRAY_SIZE(bw_calc_freqs) - 1;
	int idx = (bw > bw_calc_freqs[max_idx] * 1000000) ? max_idx : 0;

	for (; idx < max_idx; idx++) {
		u32 freq = bw_calc_freqs[idx] * 1000000;
		if (bw < freq) {
			if (idx)
				idx--;
			break;
		} else if (bw == freq)
			break;
	}
	return idx;
}

static u8 iso_share_calc_tegra210_os_idle(unsigned long iso_bw)
{
	int freq_idx = bw_calc_get_freq_idx(iso_bw);
	u8 ret;

	switch (tegra_dram_type) {
	case DRAM_TYPE_DDR3:
		ret = tegra210_ddr3_iso_efficiency_os_idle[freq_idx];
		break;
	case DRAM_TYPE_LPDDR4:
		ret = tegra210_lpddr4_iso_efficiency_os_idle[freq_idx];
		break;
	case DRAM_TYPE_LPDDR2:
		ret = tegra210_lpddr3_iso_efficiency_os_idle[freq_idx];
		break;
	}

	return ret;
}

static u8 iso_share_calc_tegra210_general(unsigned long iso_bw)
{
	int freq_idx = bw_calc_get_freq_idx(iso_bw);
	u8 ret;

	switch (tegra_dram_type) {
	case DRAM_TYPE_DDR3:
		ret = tegra210_ddr3_iso_efficiency_general[freq_idx];
		break;
	case DRAM_TYPE_LPDDR4:
		ret = tegra210_lpddr4_iso_efficiency_general[freq_idx];
		break;
	case DRAM_TYPE_LPDDR2:
		ret = tegra210_lpddr3_iso_efficiency_general[freq_idx];
		break;
	}

	return ret;
}

static u8 tegra210_emc_get_iso_share(u32 usage_flags, unsigned long iso_bw)
{
	int i;
	u8 iso_share = 100;

	if (usage_flags) {
		for (i = 0; i < ARRAY_SIZE(tegra210_emc_iso_usage); i++) {
			u8 share;
			u32 flags = tegra210_emc_iso_usage[i].emc_usage_flags;

			if (!flags)
				continue;

			share = tegra210_emc_iso_usage[i].iso_share_calculator(
						iso_bw);
			if (!share) {
				WARN(1, "%s: entry %d: iso_share 0\n",
				     __func__, i);
				continue;
			}

			if ((flags & usage_flags) == flags)
				iso_share = min(iso_share, share);
		}
	}
	last_iso_bw = iso_bw;
	tegra210_emc_iso_share = iso_share;
	return iso_share;
}

unsigned long tegra210_emc_apply_efficiency(unsigned long total_bw,
	unsigned long iso_bw, unsigned long max_rate, u32 usage_flags,
	unsigned long *iso_bw_min)
{
	u8 efficiency = tegra210_emc_get_iso_share(usage_flags, iso_bw);

	if (iso_bw && efficiency && (efficiency < 100)) {
		iso_bw /= efficiency;
		iso_bw = (iso_bw < max_rate / 100) ?
				(iso_bw * 100) : max_rate;
	}
	if (iso_bw_min)
		*iso_bw_min = iso_bw;

	efficiency = tegra210_emc_bw_efficiency;
	if (total_bw && efficiency && (efficiency < 100)) {
		total_bw = total_bw / efficiency;
		total_bw = (total_bw < max_rate / 100) ?
				(total_bw * 100) : max_rate;
	}
	return max(total_bw, iso_bw);
}

static const struct emc_clk_ops tegra210_emc_clk_ops = {
	.emc_get_rate = tegra210_emc_get_rate,
	.emc_set_rate = tegra210_emc_set_rate,
	.emc_round_rate = tegra210_emc_round_rate,
	.emc_predict_parent = tegra210_emc_predict_parent,
	.emc_apply_efficiency = tegra210_emc_apply_efficiency,
};

const struct emc_clk_ops *tegra210_emc_get_ops(void)
{
	return &tegra210_emc_clk_ops;
}
EXPORT_SYMBOL(tegra210_emc_get_ops);

void set_over_temp_timing(struct emc_table *next_timing, unsigned long state)
{
#define REFRESH_X2      1
#define REFRESH_X4      2
#define REFRESH_SPEEDUP(val, speedup)					\
		(val = ((val) & 0xFFFF0000) | (((val) & 0xFFFF) >> (speedup)))

	u32 ref = next_timing->burst_regs[EMC_REFRESH_INDEX];
	u32 pre_ref = next_timing->burst_regs[EMC_PRE_REFRESH_REQ_CNT_INDEX];
	u32 dsr_cntrl =
		next_timing->burst_regs[EMC_DYN_SELF_REF_CONTROL_INDEX];

	switch (state) {
	case TEGRA_DRAM_OVER_TEMP_NONE:
	case TEGRA_DRAM_OVER_TEMP_THROTTLE:
		break;
	case TEGRA_DRAM_OVER_TEMP_REFRESH_X2:
		REFRESH_SPEEDUP(ref, REFRESH_X2);
		REFRESH_SPEEDUP(pre_ref, REFRESH_X2);
		REFRESH_SPEEDUP(dsr_cntrl, REFRESH_X2);
		break;
	case TEGRA_DRAM_OVER_TEMP_REFRESH_X4:
		REFRESH_SPEEDUP(ref, REFRESH_X4);
		REFRESH_SPEEDUP(pre_ref, REFRESH_X4);
		REFRESH_SPEEDUP(dsr_cntrl, REFRESH_X4);
		break;
	default:
	WARN(1, "%s: Failed to set dram over temp state %lu\n",
		__func__, state);
	return;
	}

	emc_writel(ref, burst_regs_off[EMC_REFRESH_INDEX]);
	emc_writel(pre_ref, burst_regs_off[EMC_PRE_REFRESH_REQ_CNT_INDEX]);
	emc_writel(dsr_cntrl, burst_regs_off[EMC_DYN_SELF_REF_CONTROL_INDEX]);
}

static int emc_read_mrr(int dev, int addr)
{
	int ret;
	u32 val, emc_cfg;

	if (tegra_dram_type != DRAM_TYPE_LPDDR2 &&
	    tegra_dram_type != DRAM_TYPE_LPDDR4)
		return -ENODEV;

	ret = wait_for_update(EMC_EMC_STATUS, EMC_EMC_STATUS_MRR_DIVLD, false,
			      REG_EMC);
	if (ret)
		return ret;

	emc_cfg = emc_readl(EMC_CFG);
	if (emc_cfg & EMC_CFG_DRAM_ACPD) {
		emc_writel(emc_cfg & ~EMC_CFG_DRAM_ACPD, EMC_CFG);
		emc_timing_update(0);
	}

	val = dev ? DRAM_DEV_SEL_1 : DRAM_DEV_SEL_0;
	val |= (addr << EMC_MRR_MA_SHIFT) & EMC_MRR_MA_MASK;
	emc_writel(val, EMC_MRR);

	ret = wait_for_update(EMC_EMC_STATUS, EMC_EMC_STATUS_MRR_DIVLD, true,
			      REG_EMC);
	if (emc_cfg & EMC_CFG_DRAM_ACPD) {
		emc_writel(emc_cfg, EMC_CFG);
		emc_timing_update(0);
	}
	if (ret)
		return ret;

	val = emc_readl(EMC_MRR) & EMC_MRR_DATA_MASK;
	return val;
}

static int emc_get_dram_temp(void *dev, int *temp)
{
	int mr4 = 0;
	unsigned long flags;

	spin_lock_irqsave(&emc_access_lock, flags);
	mr4 = emc_read_mrr(0, 4);
	spin_unlock_irqrestore(&emc_access_lock, flags);

	if (!IS_ERR_VALUE(mr4))
		*temp = (mr4 & LPDDR2_MR4_TEMP_MASK) >> LPDDR2_MR4_TEMP_SHIFT;

	return 0;
}

static const struct thermal_zone_of_device_ops dram_therm_ops = {
	.get_temp = emc_get_dram_temp,
};

struct emc_table *emc_get_table(unsigned long over_temp_state)
{
	if ((over_temp_state == TEGRA_DRAM_OVER_TEMP_THROTTLE) &&
	    (tegra_emc_table_derated != NULL))
		return tegra_emc_table_derated;
	else
		return tegra_emc_table_normal;
}

int tegra210_emc_set_over_temp_state(unsigned long state)
{
	unsigned long flags;
	struct emc_table *current_table;
	struct emc_table *new_table;

	if ((tegra_dram_type != DRAM_TYPE_LPDDR2 &&
	     tegra_dram_type != DRAM_TYPE_LPDDR4) ||
	     !emc_timing)
		return -ENODEV;

	if (state > TEGRA_DRAM_OVER_TEMP_THROTTLE)
		return -EINVAL;

	if (state == dram_over_temp_state)
		return 0;

	spin_lock_irqsave(&emc_access_lock, flags);

	current_table = emc_get_table(dram_over_temp_state);
	new_table = emc_get_table(state);
	dram_over_temp_state = state;

	if (current_table != new_table) {
		emc_set_clock(&new_table[last_rate_idx], emc_timing, 0,
			      current_clksrc | EMC_CLK_FORCE_CC_TRIGGER);
		emc_timing = &new_table[last_rate_idx];
		tegra_emc_table = new_table;
	} else {
		set_over_temp_timing(emc_timing, state);
		emc_timing_update(0);
		if (state != TEGRA_DRAM_OVER_TEMP_NONE)
			emc_writel(EMC_REF_FORCE_CMD, EMC_REF);
	}

	spin_unlock_irqrestore(&emc_access_lock, flags);

	return 0;
}

#ifdef CONFIG_DEBUG_FS
static int emc_stats_show(struct seq_file *s, void *data)
{
	int i;

	emc_last_stats_update(TEGRA_EMC_TABLE_MAX_SIZE);

	seq_printf(s, "%-10s %-10s\n", "rate kHz", "time");
	for (i = 0; i < tegra_emc_table_size; i++) {
		if (emc_clk_sel[i].input == NULL)
			continue;

		seq_printf(s, "%-10u %-10llu\n",
			   tegra_emc_table[i].rate * 1000,
			   cputime64_to_clock_t(
					    tegra_emc_stats.time_at_clock[i]));
	}
	seq_printf(s, "%-15s %llu\n", "transitions:",
		   tegra_emc_stats.clkchange_count);
	seq_printf(s, "%-15s %llu\n", "time-stamp:",
		   cputime64_to_clock_t(tegra_emc_stats.last_update));

	return 0;
}

static int emc_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, emc_stats_show, inode->i_private);
}

static const struct file_operations emc_stats_fops = {
	.open		= emc_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int efficiency_get(void *data, u64 *val)
{
	*val = tegra210_emc_bw_efficiency;
	return 0;
}

static int efficiency_set(void *data, u64 val)
{
	tegra210_emc_bw_efficiency = (val > 100) ? 100 : val;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(efficiency_fops, efficiency_get,
			efficiency_set, "%llu\n");

static const char *emc_user_names[EMC_USER_NUM] = {
	"DC1",
	"DC2",
	"VI",
	"MSENC",
	"2D",
	"3D",
	"BB",
	"VDE",
	"VI2",
	"ISPA",
	"ISPB",
	"NVDEC",
	"NVJPG",
};

static int emc_usage_table_show(struct seq_file *s, void *data)
{
	int i, j;

	seq_printf(s, "EMC USAGE\t\tISO SHARE %% @ last bw %lu\n", last_iso_bw);

	for (i = 0; i < ARRAY_SIZE(tegra210_emc_iso_usage); i++) {
		u32 flags = tegra210_emc_iso_usage[i].emc_usage_flags;
		u8 share = tegra210_emc_iso_usage[i].iso_usage_share;
		bool fixed_share = true;
		bool first = false;

		if (tegra210_emc_iso_usage[i].iso_share_calculator) {
			share = tegra210_emc_iso_usage[i].iso_share_calculator(
				last_iso_bw);
			fixed_share = false;
		}

		seq_printf(s, "[%d]: ", i);
		if (!flags) {
			seq_puts(s, "reserved\n");
			continue;
		}

		for (j = 0; j < EMC_USER_NUM; j++) {
			u32 mask = 0x1 << j;
			if (!(flags & mask))
				continue;
			seq_printf(s, "%s%s", first ? "+" : "",
				   emc_user_names[j]);
			first = true;
		}
		seq_printf(s, "\r\t\t\t= %d(%s across bw)\n",
			   share, fixed_share ? "fixed" : "vary");
	}
	return 0;
}

static int emc_usage_table_open(struct inode *inode, struct file *file)
{
	return single_open(file, emc_usage_table_show, inode->i_private);
}

static const struct file_operations emc_usage_table_fops = {
	.open		= emc_usage_table_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int dram_temp_get(void *data, u64 *val)
{
	int temp;
	emc_get_dram_temp(data, &temp);
	*val = temp;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(dram_temp_fops, dram_temp_get, NULL,
	"%lld\n");

static int over_temp_state_get(void *data, u64 *val)
{
	*val = dram_over_temp_state;
	return 0;
}

static int over_temp_state_set(void *data, u64 val)
{
	return tegra210_emc_set_over_temp_state(val);
}
DEFINE_SIMPLE_ATTRIBUTE(over_temp_state_fops, over_temp_state_get,
			over_temp_state_set, "%llu\n");

static int tegra_emc_debug_init(void)
{
	struct dentry *emc_debugfs_root;

	if (!tegra_emc_init_done)
		return -ENODEV;

	emc_debugfs_root = debugfs_create_dir("tegra_emc", NULL);
	if (!emc_debugfs_root)
		return -ENOMEM;

	if (!debugfs_create_file("stats", S_IRUGO, emc_debugfs_root, NULL,
				 &emc_stats_fops))
		goto err_out;

	if (!debugfs_create_u32("clkchange_delay", S_IRUGO | S_IWUSR,
				emc_debugfs_root, (u32 *)&clkchange_delay))
		goto err_out;

	if (!debugfs_create_file("efficiency", S_IRUGO | S_IWUSR,
				 emc_debugfs_root, NULL, &efficiency_fops))
		goto err_out;

	if (!debugfs_create_file("emc_usage_table", S_IRUGO, emc_debugfs_root,
				 NULL, &emc_usage_table_fops))
		goto err_out;

	if (!debugfs_create_u8("emc_iso_share", S_IRUGO, emc_debugfs_root,
			       &tegra210_emc_iso_share))
		goto err_out;

	if (tegra_dram_type == DRAM_TYPE_LPDDR2 ||
		tegra_dram_type == DRAM_TYPE_LPDDR4) {
		if (!debugfs_create_file("dram_temp", S_IRUGO,
					 emc_debugfs_root, NULL,
					 &dram_temp_fops))
			goto err_out;
		if (!debugfs_create_file("over_temp_state", S_IRUGO | S_IWUSR,
					 emc_debugfs_root, NULL,
					 &over_temp_state_fops))
			goto err_out;
	}

	if (tegra_dram_type == DRAM_TYPE_LPDDR4) {
		if (!debugfs_create_u32("training_timer_period",
					S_IRUGO | S_IWUSR, emc_debugfs_root,
					&timer_period_training))
			goto err_out;
	}

	return 0;

err_out:
	debugfs_remove_recursive(emc_debugfs_root);
	return -ENOMEM;
}

late_initcall(tegra_emc_debug_init);
#endif

static const struct of_device_id mc_match[] = {
	{ .compatible = "nvidia,tegra210-mc" },
	{},
};

static const struct of_device_id car_match[] = {
	{ .compatible = "nvidia,tegra210-car" },
	{},
};

static const struct of_device_id emc_table_match[] = {
	{ .compatible = "nvidia,tegra210-emc-table" },
	{},
};

void __emc_copy_table_params(struct emc_table *src, struct emc_table *dst,
				int flags)
{
	int i;

	if (flags & EMC_COPY_TABLE_PARAM_PERIODIC_FIELDS) {
		dst->trained_dram_clktree_c0d0u0 =
			src->trained_dram_clktree_c0d0u0;
		dst->trained_dram_clktree_c0d0u1 =
			src->trained_dram_clktree_c0d0u1;
		dst->trained_dram_clktree_c0d1u0 =
			src->trained_dram_clktree_c0d1u0;
		dst->trained_dram_clktree_c0d1u1 =
			src->trained_dram_clktree_c0d1u1;
		dst->trained_dram_clktree_c1d0u0 =
			src->trained_dram_clktree_c1d0u0;
		dst->trained_dram_clktree_c1d0u1 =
			src->trained_dram_clktree_c1d0u1;
		dst->trained_dram_clktree_c1d1u0 =
			src->trained_dram_clktree_c1d1u0;
		dst->trained_dram_clktree_c1d1u1 =
			src->trained_dram_clktree_c1d1u1;
		dst->current_dram_clktree_c0d0u0 =
			src->current_dram_clktree_c0d0u0;
		dst->current_dram_clktree_c0d0u1 =
			src->current_dram_clktree_c0d0u1;
		dst->current_dram_clktree_c0d1u0 =
			src->current_dram_clktree_c0d1u0;
		dst->current_dram_clktree_c0d1u1 =
			src->current_dram_clktree_c0d1u1;
		dst->current_dram_clktree_c1d0u0 =
			src->current_dram_clktree_c1d0u0;
		dst->current_dram_clktree_c1d0u1 =
			src->current_dram_clktree_c1d0u1;
		dst->current_dram_clktree_c1d1u0 =
			src->current_dram_clktree_c1d1u0;
		dst->current_dram_clktree_c1d1u1 =
			src->current_dram_clktree_c1d1u1;
	}

	if (flags & EMC_COPY_TABLE_PARAM_TRIM_REGS) {
		for (i = 0; i < src->num_trim_per_ch; i++)
			dst->trim_perch_regs[i] = src->trim_perch_regs[i];

		for (i = 0; i < src->num_trim; i++)
			dst->trim_regs[i] = src->trim_regs[i];

		for (i = 0; i < src->num_burst_per_ch; i++)
			dst->burst_reg_per_ch[i] = src->burst_reg_per_ch[i];

		dst->trained = src->trained;
	}
}

static void emc_copy_table_params(struct emc_table *src, struct emc_table *dst,
					int table_size, int flags)
{
	int i;

	for (i = 0; i < table_size; i++)
		__emc_copy_table_params(&src[i], &dst[i], flags);
}

static int find_matching_input(struct emc_table *table, struct emc_sel *sel)
{
	u32 div_value;
	u32 src_value;
	u32 src_value_b;
	unsigned long input_rate = 0;
	struct clk *input_clk;

	div_value = emc_div_val(table->clk_src_emc);
	src_value = emc_src_val(table->clk_src_emc);

	if (div_value & 0x1) {
		pr_warn("Tegra EMC: invalid odd divider for EMC rate %u\n",
			table->rate);
		return -EINVAL;
	}

	if (src_value >= __clk_get_num_parents(emc_clk)) {
		pr_warn("Tegra EMC: no matching input found for rate %u\n",
			table->rate);
		return -EINVAL;
	}

	if (!(table->clk_src_emc & EMC_CLK_MC_EMC_SAME_FREQ) !=
	    !(MC_EMEM_ARB_MISC0_EMC_SAME_FREQ &
	    table->burst_regs[MC_EMEM_ARB_MISC0_INDEX])) {
		pr_warn("Tegra EMC: ambiguous EMC to MC ratio for rate %u\n",
			table->rate);
		return -EINVAL;
	}

	input_clk = tegra_emc_src[src_value];
	if (input_clk == tegra_emc_src[TEGRA_EMC_SRC_PLLM]) {
		input_rate = table->rate * (1 + div_value / 2);
	} else {
		input_rate = clk_get_rate(input_clk) / 1000;
		if (input_rate != (table->rate * (1 + div_value / 2))) {
			pr_warn("Tegra EMC: rate %u doesn't match input\n",
				table->rate);
			return -EINVAL;
		}
	}

	sel->input = input_clk;
	sel->input_rate = input_rate;
	sel->value = table->clk_src_emc;
	sel->input_b = input_clk;
	sel->input_rate_b = input_rate;
	sel->value_b = table->clk_src_emc;

	if (input_clk == tegra_emc_src[TEGRA_EMC_SRC_PLLM]) {
		sel->input_b = tegra_emc_src[TEGRA_EMC_SRC_PLLMB];
		src_value_b = src_value == TEGRA_EMC_SRC_PLLM_UD ?
			TEGRA_EMC_SRC_PLLMB_UD : TEGRA_EMC_SRC_PLLMB;
		sel->value_b = (table->clk_src_emc &
			~EMC_CLK_EMC_2X_CLK_SRC_MASK) |
			(src_value_b << EMC_CLK_EMC_2X_CLK_SRC_SHIFT);
	}

	return 0;
}

static void parse_dt_data(struct platform_device *pdev)
{
	u32 prop;
	int ret;
	bool has_derated_tables = false;
	struct device_node *table_node = NULL;
	struct resource r;
	int i;

	ret = of_property_read_u32(pdev->dev.of_node, "max-clock-frequency",
				   &prop);
	if (!ret)
		emc_max_rate = prop * 1000;

	if (of_find_property(pdev->dev.of_node, "has-derated-tables", NULL))
		has_derated_tables = true;

	table_node = of_find_matching_node(pdev->dev.of_node, emc_table_match);
	if (!table_node) {
		dev_err(&pdev->dev, "Can not find EMC table node\n");
		return;
	}

	if (of_address_to_resource(table_node, 0, &r)) {
		dev_err(&pdev->dev, "Can not map EMC table\n");
		return;
	}

	tegra_emc_table_normal = devm_ioremap_resource(&pdev->dev, &r);
	tegra_emc_table_size = resource_size(&r) / sizeof(struct emc_table);

	if (has_derated_tables) {
		tegra_emc_table_size /= 2;
		tegra_emc_table_derated = tegra_emc_table_normal +
					  tegra_emc_table_size;

		for (i = 0; i < tegra_emc_table_size; i++) {
			if (tegra_emc_table_derated[i].rate !=
			    tegra_emc_table_normal[i].rate) {
				dev_err(&pdev->dev, "EMC table check failed\n");
				tegra_emc_table_normal = NULL;
				tegra_emc_table_derated = NULL;
				tegra_emc_table_size = 0;
				break;
			}
		}
	}

	if (tegra_dram_type == DRAM_TYPE_LPDDR4 && tegra_emc_table_derated)
		emc_copy_table_params(tegra_emc_table_normal,
				      tegra_emc_table_derated,
				      tegra_emc_table_size,
				      EMC_COPY_TABLE_PARAM_PERIODIC_FIELDS |
				      EMC_COPY_TABLE_PARAM_TRIM_REGS);
}

static int tegra210_init_emc_data(struct platform_device *pdev)
{
	int i;
	unsigned long table_rate;
	unsigned long current_rate;

	emc_clk = devm_clk_get(&pdev->dev, "emc");
	if (IS_ERR(emc_clk)) {
		dev_err(&pdev->dev, "Can not find EMC clock\n");
		return -EINVAL;
	}

	emc_override_clk = devm_clk_get(&pdev->dev, "emc_override");
	if (IS_ERR(emc_override_clk))
		dev_err(&pdev->dev, "Cannot find EMC override clock\n");

	for (i = 0; i < TEGRA_EMC_SRC_COUNT; i++) {
		tegra_emc_src[i] = devm_clk_get(&pdev->dev,
						tegra_emc_src_names[i]);
		if (IS_ERR(tegra_emc_src[i])) {
			dev_err(&pdev->dev, "Can not find EMC source clock\n");
			return -ENODATA;
		}
	}

	tegra_emc_stats.clkchange_count = 0;
	spin_lock_init(&tegra_emc_stats.spinlock);
	tegra_emc_stats.last_update = get_jiffies_64();
	tegra_emc_stats.last_sel = TEGRA_EMC_TABLE_MAX_SIZE;

	tegra_dram_type = (emc_readl(EMC_FBIO_CFG5) &
			   EMC_FBIO_CFG5_DRAM_TYPE_MASK) >>
			   EMC_FBIO_CFG5_DRAM_TYPE_SHIFT;

	tegra_dram_dev_num = (mc_readl(MC_EMEM_ADR_CFG) & 0x1) + 1;

	if (tegra_dram_type != DRAM_TYPE_DDR3 &&
	    tegra_dram_type != DRAM_TYPE_LPDDR2 &&
	    tegra_dram_type != DRAM_TYPE_LPDDR4) {
		dev_err(&pdev->dev, "DRAM not supported\n");
		return -ENODATA;
	}

	parse_dt_data(pdev);
	if (!tegra_emc_table_size ||
	    tegra_emc_table_size > TEGRA_EMC_TABLE_MAX_SIZE) {
		dev_err(&pdev->dev, "Invalid table size %d\n",
			tegra_emc_table_size);
		return -EINVAL;
	}
	tegra_emc_table = tegra_emc_table_normal;

	seq = supported_seqs;
	while (seq->table_rev) {
		if (seq->table_rev == tegra_emc_table[0].rev)
			break;
		seq++;
	}
	if (!seq->set_clock) {
		seq = NULL;
		dev_err(&pdev->dev, "Invalid EMC sequence for table Rev. %d\n",
			tegra_emc_table[0].rev);
		return -EINVAL;
	}

	emc_clk_sel = devm_kcalloc(&pdev->dev,
				   tegra_emc_table_size,
				   sizeof(struct emc_sel),
				   GFP_KERNEL);
	if (!emc_clk_sel) {
		dev_err(&pdev->dev, "Memory allocation failed\n");
		return -ENOMEM;
	}

	current_rate = clk_get_rate(emc_clk) / 1000;
	for (i = 0; i < tegra_emc_table_size; i++) {
		table_rate = tegra_emc_table[i].rate;
		if (!table_rate)
			continue;

		if (emc_max_rate && table_rate > emc_max_rate)
			break;

		if (i && ((table_rate <= tegra_emc_table[i-1].rate) ||
		   (tegra_emc_table[i].min_volt <
		    tegra_emc_table[i-1].min_volt)))
			continue;

		if (tegra_emc_table[i].rev != tegra_emc_table[0].rev)
			continue;

		if (find_matching_input(&tegra_emc_table[i], &emc_clk_sel[i]))
			continue;

		if (table_rate == current_rate)
			tegra_emc_stats.last_sel = i;
	}

	dev_info(&pdev->dev, "validated EMC DFS table\n");

	start_timing.num_burst = tegra_emc_table[0].num_burst;
	start_timing.num_burst_per_ch =
		tegra_emc_table[0].num_burst_per_ch;
	start_timing.num_trim = tegra_emc_table[0].num_trim;
	start_timing.num_trim_per_ch =
		tegra_emc_table[0].num_trim_per_ch;
	start_timing.num_mc_regs = tegra_emc_table[0].num_mc_regs;
	start_timing.num_up_down = tegra_emc_table[0].num_up_down;
	start_timing.vref_num =
		tegra_emc_table[0].vref_num;

	return 0;
}

static int tegra210_emc_probe(struct platform_device *pdev)
{
	struct device_node *node;
	struct resource *r;
	int ret;

	node = of_find_matching_node(NULL, mc_match);
	if (!node) {
		dev_err(&pdev->dev, "Error finding MC device.\n");
		return -EINVAL;
	}

	mc_base = of_iomap(node, 0);
	if (!mc_base) {
		dev_err(&pdev->dev, "Can't map MC registers\n");
		return -EINVAL;
	}

	node = of_find_matching_node(NULL, car_match);
	if (!node) {
		dev_err(&pdev->dev, "Error finding CAR device.\n");
		return -EINVAL;
	}

	clk_base = of_iomap(node, 0);
	if (!clk_base) {
		dev_err(&pdev->dev, "Can't map CAR registers\n");
		return -EINVAL;
	}

	tegra_ram_code = tegra_read_ram_code();
	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	emc_base = devm_ioremap_resource(&pdev->dev, r);
	r = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	emc0_base = devm_ioremap_resource(&pdev->dev, r);
	r = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	emc1_base = devm_ioremap_resource(&pdev->dev, r);

	ret = tegra210_init_emc_data(pdev);
	if (ret)
		return ret;

	tegra_emc_init_done = true;

	tegra_emc_debug_init();

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int tegra210_emc_suspend(struct device *dev)
{
	if (!IS_ERR(emc_override_clk)) {
		emc_override_rate = clk_get_rate(emc_override_clk);
		clk_set_rate(emc_override_clk, 204000000);
		clk_prepare_enable(emc_override_clk);
	}

	return 0;
}

static int tegra210_emc_resume(struct device *dev)
{
	if (!IS_ERR(emc_override_clk)) {
		clk_set_rate(emc_override_clk, emc_override_rate);
		clk_disable_unprepare(emc_override_clk);
	}
	return 0;
}
#endif

static const struct dev_pm_ops tegra210_emc_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(tegra210_emc_suspend, tegra210_emc_resume)
};

static struct of_device_id tegra210_emc_of_match[] = {
	{ .compatible = "nvidia,tegra210-emc", },
	{ },
};

static struct platform_driver tegra210_emc_driver = {
	.driver         = {
		.name   = "tegra210-emc",
		.of_match_table = tegra210_emc_of_match,
		.pm	= &tegra210_emc_pm_ops,
	},
	.probe          = tegra210_emc_probe,
};

static int __init tegra210_emc_init(void)
{
	return platform_driver_register(&tegra210_emc_driver);
}
subsys_initcall(tegra210_emc_init);

static int __init tegra210_emc_late_init(void)
{
	struct device_node *node;
	struct platform_device *pdev;

	if (!tegra_emc_init_done)
		return -ENODEV;

	node = of_find_matching_node(NULL, tegra210_emc_of_match);
	if (!node) {
		dev_err(&pdev->dev, "Error finding EMC node.\n");
		return -EINVAL;
	}

	pdev = of_find_device_by_node(node);
	if (!pdev) {
		dev_err(&pdev->dev, "Error finding EMC device.\n");
		return -EINVAL;
	}

	thermal_zone_of_sensor_register(&pdev->dev, 0, NULL, &dram_therm_ops);

	return 0;
}
late_initcall(tegra210_emc_late_init);
