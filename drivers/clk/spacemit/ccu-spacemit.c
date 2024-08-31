// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 SpacemiT Technology Co. Ltd
 * Copyright (c) 2024 Haylen Chu <heylenay@outlook.com>
 */

#include <linux/delay.h>
#include <dt-bindings/clock/spacemit,ccu.h>
#include <linux/clk-provider.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>

#include "ccu_common.h"
#include "ccu_pll.h"
#include "ccu_mix.h"
#include "ccu_ddn.h"

/*	APBS register offset	*/
/*	pll1	*/
#define APB_SPARE1_REG			0x100
#define APB_SPARE2_REG			0x104
#define APB_SPARE3_REG			0x108
/*	pll2	*/
#define APB_SPARE7_REG			0x118
#define APB_SPARE8_REG			0x11c
#define APB_SPARE9_REG			0x120
/*	pll3	*/
#define APB_SPARE10_REG			0x124
#define APB_SPARE11_REG			0x128
#define APB_SPARE12_REG			0x12c

/* MPMU register offset */
#define MPMU_POSR			0x10
#define POSR_PLL1_LOCK			BIT(27)
#define POSR_PLL2_LOCK			BIT(28)
#define POSR_PLL3_LOCK			BIT(29)

#define MPMU_WDTPCR			0x200
#define MPMU_RIPCCR			0x210
#define MPMU_ACGR			0x1024
#define MPMU_SUCCR			0x14
#define MPMU_ISCCR			0x44
#define MPMU_SUCCR_1			0x10b0
#define MPMU_APBCSCR			0x1050

/* APBC register offset */
#define APBC_UART1_CLK_RST		0x0
#define APBC_UART2_CLK_RST		0x4
#define APBC_UART3_CLK_RST		0x24
#define APBC_UART4_CLK_RST		0x70
#define APBC_UART5_CLK_RST		0x74
#define APBC_UART6_CLK_RST		0x78
#define APBC_UART7_CLK_RST		0x94
#define APBC_UART8_CLK_RST		0x98
#define APBC_UART9_CLK_RST		0x9c

/* APMU register offset */
#define APMU_CCI550_CLK_CTRL		0x300
#define APMU_CPU_C0_CLK_CTRL		0x38C
#define APMU_CPU_C1_CLK_CTRL		0x390

/*	APBS clocks start	*/

static const struct ccu_pll_rate_tbl pll2_rate_tbl[] = {
	CCU_PLL_RATE(3000000000UL, 0x66, 0xdd, 0x50, 0x00, 0x3f, 0xe00000),
	CCU_PLL_RATE(3200000000UL, 0x67, 0xdd, 0x50, 0x00, 0x43, 0xeaaaab),
	CCU_PLL_RATE(2457600000UL, 0x64, 0xdd, 0x50, 0x00, 0x33, 0x0ccccd),
	CCU_PLL_RATE(2800000000UL, 0x66, 0xdd, 0x50, 0x00, 0x3a, 0x155555),
};

static const struct ccu_pll_rate_tbl pll3_rate_tbl[] = {
	CCU_PLL_RATE(3000000000UL, 0x66, 0xdd, 0x50, 0x00, 0x3f, 0xe00000),
	CCU_PLL_RATE(3200000000UL, 0x67, 0xdd, 0x50, 0x00, 0x43, 0xeaaaab),
	CCU_PLL_RATE(2457600000UL, 0x64, 0xdd, 0x50, 0x00, 0x33, 0x0ccccd),
};

static CCU_PLL_DEFINE(pll2, "pll2", pll2_rate_tbl,
		      APB_SPARE7_REG, APB_SPARE8_REG, APB_SPARE9_REG,
		      MPMU_POSR, POSR_PLL2_LOCK, 0);
static CCU_PLL_DEFINE(pll3, "pll3", pll3_rate_tbl,
		      APB_SPARE10_REG, APB_SPARE11_REG, APB_SPARE12_REG,
		      MPMU_POSR, POSR_PLL3_LOCK, 0);

static CCU_GATE_FACTOR_DEFINE(pll1_d2, "pll1_d2", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(1), BIT(1), 0, 2, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d3, "pll1_d3", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(2), BIT(2), 0, 3, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d4, "pll1_d4", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(3), BIT(3), 0, 4, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d5, "pll1_d5", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(4), BIT(4), 0, 5, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d6, "pll1_d6", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(5), BIT(5), 0, 6, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d7, "pll1_d7", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(6), BIT(6), 0, 7, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d8, "pll1_d8", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(7), BIT(7), 0, 8, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d11_223p4, "pll1_d11_223p4",
			      "pll1_2457p6_vco", APB_SPARE2_REG,
			      BIT(15), BIT(15), 0, 11, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d13_189, "pll1_d13_189", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(16), BIT(16), 0, 13, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d23_106p8, "pll1_d23_106p8",
			      "pll1_2457p6_vco", APB_SPARE2_REG,
			      BIT(20), BIT(20), 0, 23, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d64_38p4, "pll1_d64_38p4", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(0), BIT(0), 0, 64, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_aud_245p7, "pll1_aud_245p7",
			      "pll1_2457p6_vco", APB_SPARE2_REG,
			      BIT(10), BIT(10), 0, 10, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_aud_24p5, "pll1_aud_24p5", "pll1_2457p6_vco",
			      APB_SPARE2_REG,
			      BIT(11), BIT(11), 0, 100, 1, 0);

static CCU_GATE_FACTOR_DEFINE(pll2_d1, "pll2_d1", "pll2", APB_SPARE8_REG,
			      BIT(0), BIT(0), 0, 1, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll2_d2, "pll2_d2", "pll2", APB_SPARE8_REG,
			      BIT(1), BIT(1), 0, 2, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll2_d3, "pll2_d3", "pll2", APB_SPARE8_REG,
			      BIT(2), BIT(2), 0, 3, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll2_d4, "pll2_d4", "pll2", APB_SPARE8_REG,
			      BIT(3), BIT(3), 0, 4, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll2_d5, "pll2_d5", "pll2", APB_SPARE8_REG,
			      BIT(4), BIT(4), 0, 5, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll2_d6, "pll2_d6", "pll2", APB_SPARE8_REG,
			      BIT(5), BIT(5), 0, 6, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll2_d7, "pll2_d7", "pll2", APB_SPARE8_REG,
			      BIT(6), BIT(6), 0, 7, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll2_d8, "pll2_d8", "pll2", APB_SPARE8_REG,
			      BIT(7), BIT(7), 0, 8, 1, 0);

static CCU_GATE_FACTOR_DEFINE(pll3_d1, "pll3_d1", "pll3", APB_SPARE11_REG,
			      BIT(0), BIT(0), 0, 1, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll3_d2, "pll3_d2", "pll3", APB_SPARE11_REG,
			      BIT(1), BIT(1), 0, 2, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll3_d3, "pll3_d3", "pll3", APB_SPARE11_REG,
			      BIT(2), BIT(2), 0, 3, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll3_d4, "pll3_d4", "pll3", APB_SPARE11_REG,
			      BIT(3), BIT(3), 0, 4, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll3_d5, "pll3_d5", "pll3", APB_SPARE11_REG,
			      BIT(4), BIT(4), 0, 5, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll3_d6, "pll3_d6", "pll3", APB_SPARE11_REG,
			      BIT(5), BIT(5), 0, 6, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll3_d7, "pll3_d7", "pll3", APB_SPARE11_REG,
			      BIT(6), BIT(6), 0, 7, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll3_d8, "pll3_d8", "pll3", APB_SPARE11_REG,
			      BIT(7), BIT(7), 0, 8, 1, 0);

static CCU_FACTOR_DEFINE(pll3_20, "pll3_20", "pll3_d8", 20, 1);
static CCU_FACTOR_DEFINE(pll3_40, "pll3_40", "pll3_d8", 10, 1);
static CCU_FACTOR_DEFINE(pll3_80, "pll3_80", "pll3_d8", 5, 1);

/*	APBS clocks end		*/

/*	MPMU clocks start	*/
static CCU_GATE_DEFINE(pll1_d8_307p2, "pll1_d8_307p2", "pll1_d8",
	MPMU_ACGR,
	BIT(13), BIT(13), 0, 0);
static CCU_FACTOR_DEFINE(pll1_d32_76p8, "pll1_d32_76p8", "pll1_d8_307p2",
			 4, 1);
static CCU_FACTOR_DEFINE(pll1_d40_61p44, "pll1_d40_61p44", "pll1_d8_307p2",
			 5, 1);
static CCU_FACTOR_DEFINE(pll1_d16_153p6, "pll1_d16_153p6", "pll1_d8",
			 2, 1);
static CCU_GATE_FACTOR_DEFINE(pll1_d24_102p4, "pll1_d24_102p4", "pll1_d8",
			      MPMU_ACGR,
			      BIT(12), BIT(12), 0, 3, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d48_51p2, "pll1_d48_51p2", "pll1_d8",
			      MPMU_ACGR,
			      BIT(7), BIT(7), 0, 6, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d48_51p2_ap, "pll1_d48_51p2_ap", "pll1_d8",
			      MPMU_ACGR,
			      BIT(11), BIT(11), 0, 6, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_m3d128_57p6, "pll1_m3d128_57p6", "pll1_d8",
			      MPMU_ACGR,
			      BIT(8), BIT(8), 0, 16, 3, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d96_25p6, "pll1_d96_25p6", "pll1_d8",
			      MPMU_ACGR,
			      BIT(4), BIT(4), 0, 12, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d192_12p8, "pll1_d192_12p8", "pll1_d8",
			      MPMU_ACGR,
			      BIT(3), BIT(3), 0, 24, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d192_12p8_wdt, "pll1_d192_12p8_wdt",
			      "pll1_d8", MPMU_ACGR,
			      BIT(19), BIT(19), 0x0, 24, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d384_6p4, "pll1_d384_6p4", "pll1_d8",
			      MPMU_ACGR,
			      BIT(2), BIT(2), 0, 48, 1, 0);
static CCU_FACTOR_DEFINE(pll1_d768_3p2, "pll1_d768_3p2", "pll1_d384_6p4",
			 2, 1);
static CCU_FACTOR_DEFINE(pll1_d1536_1p6, "pll1_d1536_1p6", "pll1_d384_6p4",
			 4, 1);
static CCU_FACTOR_DEFINE(pll1_d3072_0p8, "pll1_d3072_0p8", "pll1_d384_6p4",
			 8, 1);

static CCU_FACTOR_DEFINE(pll1_d7_351p08, "pll1_d7_351p08", "pll1_d7",
			 1, 1);

static CCU_GATE_DEFINE(pll1_d6_409p6, "pll1_d6_409p6", "pll1_d6",
		       MPMU_ACGR,
		       BIT(0), BIT(0), 0, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d12_204p8, "pll1_d12_204p8", "pll1_d6",
			      MPMU_ACGR,
			      BIT(5), BIT(5), 0, 2, 1, 0);

static CCU_GATE_DEFINE(pll1_d5_491p52, "pll1_d5_491p52", "pll1_d5",
		       MPMU_ACGR, BIT(21), BIT(21), 0, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d10_245p76, "pll1_d10_245p76", "pll1_d5",
			      MPMU_ACGR,
			      BIT(18), BIT(18), 0, 2, 1, 0);

static CCU_GATE_DEFINE(pll1_d4_614p4, "pll1_d4_614p4", "pll1_d4",
		       MPMU_ACGR,
		       BIT(15), BIT(15), 0, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d52_47p26, "pll1_d52_47p26", "pll1_d4",
			      MPMU_ACGR,
			      BIT(10), BIT(10), 0, 13, 1, 0);
static CCU_GATE_FACTOR_DEFINE(pll1_d78_31p5, "pll1_d78_31p5", "pll1_d4",
			      MPMU_ACGR,
			      BIT(6), BIT(6), 0, 39, 2, 0);

static CCU_GATE_DEFINE(pll1_d3_819p2, "pll1_d3_819p2", "pll1_d3",
		       MPMU_ACGR,
		       BIT(14), BIT(14), 0, 0);

static CCU_GATE_DEFINE(pll1_d2_1228p8, "pll1_d2_1228p8", "pll1_d2",
		       MPMU_ACGR,
		       BIT(16), BIT(16), 0, 0);

static struct ccu_ddn_info uart_ddn_mask_info = {
	.factor		= 2,
	.num_mask	= 0x1fff,
	.den_mask	= 0x1fff,
	.num_shift	= 16,
	.den_shift	= 0,
};
static struct ccu_ddn_tbl slow_uart1_tbl[] = {
	{ .num = 125, .den = 24 },
};
static struct ccu_ddn_tbl slow_uart2_tbl[] = {
	{ .num = 6144, .den = 960 },
};
static CCU_GATE_NO_PARENT_DEFINE(slow_uart, "slow_uart",
				 MPMU_ACGR,
				 BIT(1), BIT(1), 0, 0);
static CCU_DDN_DEFINE(slow_uart1_14p74, "slow_uart1_14p74", "pll1_d16_153p6",
		      &uart_ddn_mask_info, slow_uart1_tbl,
		      MPMU_SUCCR, 0);
static CCU_DDN_DEFINE(slow_uart2_48, "slow_uart2_48", "pll1_d4_614p4",
		      &uart_ddn_mask_info, slow_uart2_tbl,
		      MPMU_SUCCR_1, 0);
/*	MPMU clocks end		*/

/*	APBC clocks start	*/
static const char * const uart_clk_parents[] = {
	"pll1_m3d128_57p6", "slow_uart1_14p74", "slow_uart2_48",
};
static CCU_MUX_GATE_DEFINE(uart0_clk, "uart0_clk", uart_clk_parents,
			   APBC_UART1_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart2_clk, "uart2_clk", uart_clk_parents,
			   APBC_UART2_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart3_clk, "uart3_clk", uart_clk_parents,
			   APBC_UART3_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart4_clk, "uart4_clk", uart_clk_parents,
			   APBC_UART4_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart5_clk, "uart5_clk", uart_clk_parents,
			   APBC_UART5_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart6_clk, "uart6_clk", uart_clk_parents,
			   APBC_UART6_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart7_clk, "uart7_clk", uart_clk_parents,
			   APBC_UART7_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart8_clk, "uart8_clk", uart_clk_parents,
			   APBC_UART8_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
static CCU_MUX_GATE_DEFINE(uart9_clk, "uart9_clk", uart_clk_parents,
			   APBC_UART9_CLK_RST,
			   4, 3, 0x3, 0x3, 0x0,
			   0);
/*	APBC clocks end		*/

/*	APMU clocks start	*/
static const char * const cci550_clk_parents[] = {
	"pll1_d5_491p52", "pll1_d4_614p4", "pll1_d3_819p2", "pll2_d3"
};
static CCU_DIV_FC_MUX_DEFINE(cci550_clk, "cci550_clk", cci550_clk_parents,
			     APMU_CCI550_CLK_CTRL,
			     8, 3, BIT(12), 0, 2, CLK_IS_CRITICAL);

static const char * const cpu_c0_hi_clk_parents[] = { "pll3_d2", "pll3_d1" };
static CCU_MUX_DEFINE(cpu_c0_hi_clk, "cpu_c0_hi_clk", cpu_c0_hi_clk_parents,
		      APMU_CPU_C0_CLK_CTRL,
		      13, 1, 0);
static const char * const cpu_c0_clk_parents[] = {
	"pll1_d4_614p4", "pll1_d3_819p2", "pll1_d6_409p6", "pll1_d5_491p52",
	"pll1_d2_1228p8", "pll3_d3", "pll2_d3", "cpu_c0_hi_clk"
};
static CCU_MUX_FC_DEFINE(cpu_c0_core_clk, "cpu_c0_core_clk", cpu_c0_clk_parents,
			 APMU_CPU_C0_CLK_CTRL,
			 BIT(12), 0, 3, CLK_IS_CRITICAL);
static CCU_DIV_DEFINE(cpu_c0_ace_clk, "cpu_c0_ace_clk", "cpu_c0_core_clk",
		      APMU_CPU_C0_CLK_CTRL,
		      6, 3, CLK_IS_CRITICAL);
static CCU_DIV_DEFINE(cpu_c0_tcm_clk, "cpu_c0_tcm_clk", "cpu_c0_core_clk",
		      APMU_CPU_C0_CLK_CTRL, 9, 3, CLK_IS_CRITICAL);

static const char * const cpu_c1_hi_clk_parents[] = { "pll3_d2", "pll3_d1" };
static CCU_MUX_DEFINE(cpu_c1_hi_clk, "cpu_c1_hi_clk", cpu_c1_hi_clk_parents,
		      APMU_CPU_C1_CLK_CTRL,
		      13, 1, CLK_IS_CRITICAL);
static const char * const cpu_c1_clk_parents[] = {
	"pll1_d4_614p4", "pll1_d3_819p2", "pll1_d6_409p6", "pll1_d5_491p52",
	"pll1_d2_1228p8", "pll3_d3", "pll2_d3", "cpu_c1_hi_clk"
};
static CCU_MUX_FC_DEFINE(cpu_c1_core_clk, "cpu_c1_core_clk", cpu_c1_clk_parents,
			 APMU_CPU_C1_CLK_CTRL,
			 BIT(12), 0, 3, CLK_IS_CRITICAL);
static CCU_DIV_DEFINE(cpu_c1_ace_clk, "cpu_c1_ace_clk", "cpu_c1_core_clk",
		      APMU_CPU_C1_CLK_CTRL,
		      6, 3, CLK_IS_CRITICAL);
/*	APMU clocks end		*/

static struct clk_hw_onecell_data spacemit_ccu_apbs_clks = {
	.hws = {
		[CLK_PLL2]		= &pll2.common.hw,
		[CLK_PLL3]		= &pll3.common.hw,
		[CLK_PLL1_D2]		= &pll1_d2.common.hw,
		[CLK_PLL1_D3]		= &pll1_d3.common.hw,
		[CLK_PLL1_D4]		= &pll1_d4.common.hw,
		[CLK_PLL1_D5]		= &pll1_d5.common.hw,
		[CLK_PLL1_D6]		= &pll1_d6.common.hw,
		[CLK_PLL1_D7]		= &pll1_d7.common.hw,
		[CLK_PLL1_D8]		= &pll1_d8.common.hw,
		[CLK_PLL1_D11]		= &pll1_d11_223p4.common.hw,
		[CLK_PLL1_D13]		= &pll1_d13_189.common.hw,
		[CLK_PLL1_D23]		= &pll1_d23_106p8.common.hw,
		[CLK_PLL1_D64]		= &pll1_d64_38p4.common.hw,
		[CLK_PLL1_D10_AUD]	= &pll1_aud_245p7.common.hw,
		[CLK_PLL1_D100_AUD]	= &pll1_aud_24p5.common.hw,
		[CLK_PLL2_D1]		= &pll2_d1.common.hw,
		[CLK_PLL2_D2]		= &pll2_d2.common.hw,
		[CLK_PLL2_D3]		= &pll2_d3.common.hw,
		[CLK_PLL2_D3]		= &pll2_d4.common.hw,
		[CLK_PLL2_D5]		= &pll2_d5.common.hw,
		[CLK_PLL2_D6]		= &pll2_d6.common.hw,
		[CLK_PLL2_D7]		= &pll2_d7.common.hw,
		[CLK_PLL2_D8]		= &pll2_d8.common.hw,
		[CLK_PLL3_D1]		= &pll3_d1.common.hw,
		[CLK_PLL3_D2]		= &pll3_d2.common.hw,
		[CLK_PLL3_D3]		= &pll3_d3.common.hw,
		[CLK_PLL3_D4]		= &pll3_d4.common.hw,
		[CLK_PLL3_D5]		= &pll3_d5.common.hw,
		[CLK_PLL3_D6]		= &pll3_d6.common.hw,
		[CLK_PLL3_D7]		= &pll3_d7.common.hw,
		[CLK_PLL3_D8]		= &pll3_d8.common.hw,
		[CLK_PLL3_80]		= &pll3_80.common.hw,
		[CLK_PLL3_40]		= &pll3_40.common.hw,
		[CLK_PLL3_20]		= &pll3_20.common.hw,

	},
	.num = CLK_APBS_NUM,
};

static struct clk_hw_onecell_data spacemit_ccu_mpmu_clks = {
	.hws = {
		[CLK_PLL1_307P2]	= &pll1_d8_307p2.common.hw,
		[CLK_PLL1_76P8]		= &pll1_d32_76p8.common.hw,
		[CLK_PLL1_61P44]	= &pll1_d40_61p44.common.hw,
		[CLK_PLL1_153P6]	= &pll1_d16_153p6.common.hw,
		[CLK_PLL1_102P4]	= &pll1_d24_102p4.common.hw,
		[CLK_PLL1_51P2]		= &pll1_d48_51p2.common.hw,
		[CLK_PLL1_51P2_AP]	= &pll1_d48_51p2_ap.common.hw,
		[CLK_PLL1_57P6]		= &pll1_m3d128_57p6.common.hw,
		[CLK_PLL1_25P6]		= &pll1_d96_25p6.common.hw,
		[CLK_PLL1_12P8]		= &pll1_d192_12p8.common.hw,
		[CLK_PLL1_12P8_WDT]	= &pll1_d192_12p8_wdt.common.hw,
		[CLK_PLL1_6P4]		= &pll1_d384_6p4.common.hw,
		[CLK_PLL1_3P2]		= &pll1_d768_3p2.common.hw,
		[CLK_PLL1_1P6]		= &pll1_d1536_1p6.common.hw,
		[CLK_PLL1_0P8]		= &pll1_d3072_0p8.common.hw,
		[CLK_PLL1_351]		= &pll1_d7_351p08.common.hw,
		[CLK_PLL1_409P6]	= &pll1_d6_409p6.common.hw,
		[CLK_PLL1_204P8]	= &pll1_d12_204p8.common.hw,
		[CLK_PLL1_491]		= &pll1_d5_491p52.common.hw,
		[CLK_PLL1_245P76]	= &pll1_d10_245p76.common.hw,
		[CLK_PLL1_614]		= &pll1_d4_614p4.common.hw,
		[CLK_PLL1_47P26]	= &pll1_d52_47p26.common.hw,
		[CLK_PLL1_31P5]		= &pll1_d78_31p5.common.hw,
		[CLK_PLL1_819]		= &pll1_d3_819p2.common.hw,
		[CLK_PLL1_1228]		= &pll1_d2_1228p8.common.hw,
		[CLK_SLOW_UART]		= &slow_uart.common.hw,
		[CLK_SLOW_UART1]	= &slow_uart1_14p74.common.hw,
		[CLK_SLOW_UART2]	= &slow_uart2_48.common.hw,
	},
	.num = CLK_SLOW_UART2 + 1,
};

static struct clk_hw_onecell_data spacemit_ccu_apbc_clks = {
	.hws = {
		[CLK_UART0]		= &uart0_clk.common.hw,
		[CLK_UART2]		= &uart2_clk.common.hw,
		[CLK_UART3]		= &uart3_clk.common.hw,
		[CLK_UART4]		= &uart4_clk.common.hw,
		[CLK_UART5]		= &uart5_clk.common.hw,
		[CLK_UART6]		= &uart6_clk.common.hw,
		[CLK_UART7]		= &uart7_clk.common.hw,
		[CLK_UART8]		= &uart8_clk.common.hw,
		[CLK_UART9]		= &uart9_clk.common.hw,
	},
	.num = CLK_UART9 + 1,
};

static struct clk_hw_onecell_data spacemit_ccu_apmu_clks = {
	.hws = {
		[CLK_CCI550]		= &cci550_clk.common.hw,
		[CLK_CPU_C0_HI]		= &cpu_c0_hi_clk.common.hw,
		[CLK_CPU_C0_CORE]	= &cpu_c0_core_clk.common.hw,
		[CLK_CPU_C0_ACE]	= &cpu_c0_ace_clk.common.hw,
		[CLK_CPU_C0_TCM]	= &cpu_c0_tcm_clk.common.hw,
		[CLK_CPU_C1_HI]		= &cpu_c1_hi_clk.common.hw,
		[CLK_CPU_C1_CORE]	= &cpu_c1_core_clk.common.hw,
		[CLK_CPU_C1_ACE]	= &cpu_c1_ace_clk.common.hw,
	},
	.num = CLK_CPU_C1_ACE + 1,
};

struct spacemit_ccu_data {
	struct clk_hw_onecell_data *hw_clks;
	bool need_pll_lock;
};

struct spacemit_ccu_priv {
	const struct spacemit_ccu_data *data;
	struct regmap *base;
	struct regmap *lock_base;
	spinlock_t lock;
};

static int spacemit_ccu_register(struct device *dev,
				 struct spacemit_ccu_priv *priv)
{
	const struct spacemit_ccu_data *data = priv->data;
	int i, ret;

	for (i = 0; i < data->hw_clks->num; i++) {
		struct clk_hw *hw = data->hw_clks->hws[i];
		struct ccu_common *common;
		const char *name;

		if (!hw)
			continue;

		common = hw_to_ccu_common(hw);
		name = hw->init->name;

		common->lock		= &priv->lock;
		common->base		= priv->base;
		common->lock_base	= priv->lock_base;

		ret = devm_clk_hw_register(dev, hw);
		if (ret) {
			dev_err(dev, "Cannot register clock %d - %s\n",
				i, name);
			return ret;
		}
	}

	return devm_of_clk_add_hw_provider(dev, of_clk_hw_onecell_get,
					   data->hw_clks);
}

static int spacemit_ccu_probe(struct platform_device *pdev)
{
	const struct spacemit_ccu_data *data;
	struct regmap *base_map, *lock_map;
	struct device *dev = &pdev->dev;
	struct spacemit_ccu_priv *priv;
	struct device_node *parent;
	int ret;

	data = of_device_get_match_data(dev);
	if (WARN_ON(!data))
		return -EINVAL;

	parent   = of_get_parent(dev->of_node);
	base_map = syscon_node_to_regmap(parent);
	of_node_put(parent);

	if (IS_ERR(base_map))
		return dev_err_probe(dev, PTR_ERR(base_map),
				     "failed to get regmap\n");

	if (data->need_pll_lock) {
		lock_map = syscon_regmap_lookup_by_phandle(dev->of_node,
							   "spacemit,mpmu");
		if (IS_ERR(lock_map))
			return dev_err_probe(dev, PTR_ERR(lock_map),
					     "failed to get lock regmap\n");
	}

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->data	= data;
	priv->base	= base_map;
	priv->lock_base	= lock_map;
	spin_lock_init(&priv->lock);

	ret = spacemit_ccu_register(dev, priv);
	if (ret)
		return dev_err_probe(dev, ret, "failed to register clocks");

	return 0;
}

static const struct spacemit_ccu_data spacemit_ccu_apbs_data = {
	.need_pll_lock	= true,
	.hw_clks	= &spacemit_ccu_apbs_clks,
};

static const struct spacemit_ccu_data spacemit_ccu_mpmu_data = {
	.need_pll_lock	= false,
	.hw_clks	= &spacemit_ccu_mpmu_clks,
};

static const struct spacemit_ccu_data spacemit_ccu_apbc_data = {
	.need_pll_lock	= false,
	.hw_clks	= &spacemit_ccu_apbc_clks,
};

static const struct spacemit_ccu_data spacemit_ccu_apmu_data = {
	.need_pll_lock	= false,
	.hw_clks	= &spacemit_ccu_apmu_clks,
};

static const struct of_device_id of_spacemit_ccu_match[] = {
	{
		.compatible	= "spacemit,ccu-apbs",
		.data		= &spacemit_ccu_apbs_data,
	},
	{
		.compatible	= "spacemit,ccu-mpmu",
		.data		= &spacemit_ccu_mpmu_data,
	},
	{
		.compatible	= "spacemit,ccu-apbc",
		.data		= &spacemit_ccu_apbc_data,
	},
	{
		.compatible	= "spacemit,ccu-apmu",
		.data		= &spacemit_ccu_apmu_data,
	},
	{ }
};
MODULE_DEVICE_TABLE(of, of_spacemit_ccu_match);

static struct platform_driver spacemit_ccu_driver = {
	.driver = {
		.name		= "spacemit,ccu",
		.of_match_table = of_spacemit_ccu_match,
	},
	.probe	= spacemit_ccu_probe,
};
module_platform_driver(spacemit_ccu_driver);

MODULE_DESCRIPTION("Spacemit CCU driver");
MODULE_AUTHOR("Haylen Chu <heylenay@outlook.com>");
MODULE_LICENSE("GPL");
