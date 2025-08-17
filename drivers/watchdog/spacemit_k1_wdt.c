// SPDX-License-Identifier: GPL-v2-only

#include <linux/printk.h>
#include <linux/dev_printk.h>
#include <linux/platform_device.h>
#include <linux/watchdog.h>
#include <linux/clk.h>
#include <linux/reset.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/container_of.h>
#include <linux/interrupt.h>

#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#define DRIVER_NAME KBUILD_MODNAME

#define WDT_FIRST_ACCESS	0xb0
#define WDT_FIRST_ACCESS_KEY	0xbaba

#define WDT_SECOND_ACCESS	0xb4
#define WDT_SECOND_ACCESS_KEY	0xeb10

#define WDT_MATCH_ENABLE	0xb8

#define WDT_MATCH_EXPIRE_ENABLE	BIT(0)
/* Unset: generate interrupt, set: generate system reset */
#define WDT_MATCH_EXPIRE_RESET	BIT(1)

#define WDT_MATCH_VALUE		0xbc

#define WDT_STATUS		0xc0
#define WDT_INTERRUPT_CLEAR	0xc4
#define WDT_COUNTER_RESET	0xc8
#define WDT_VALUE		0xcc

#define WDT_TICK_SHIFT 8
#define WDT_TICK_RATE (1<<WDT_TICK_SHIFT)
#define WDT_TICKS_TO_TIME(ticks) ((ticks) >> WDT_TICK_SHIFT)
#define WDT_TIME_TO_TICKS(time) ((time) << WDT_TICK_SHIFT)
#define WDT_TICKS_MAX ((1U << 16) - 1)
#define WDT_TIMEOUT 60

#define WDT_EARLY_ENABLE 0

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started (default="
		__MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

static int timeout = WDT_TIMEOUT;
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout, "Watchdog timeout in seconds (default="
		__MODULE_STRING(WDT_TIMEOUT) "s)");

static bool early_enable = WDT_EARLY_ENABLE;
module_param(early_enable, bool, WDT_EARLY_ENABLE);
MODULE_PARM_DESC(early_enable, "Enable watchdog when driver is loaded (default="
		__MODULE_STRING(WDT_EARLY_ENABLE) ")");

struct k1_wdt {
	struct platform_device *pdev;
	struct watchdog_device wdd;
	struct clk *core_clk;
	struct clk *bus_clk;
	struct reset_control *reset;
	void __iomem *base;
	bool pretimeout_expired;
};

static inline uint32_t k1_wdt_read(struct k1_wdt *wdt, int reg)
{
	return readl(wdt->base + reg);
}

static inline void k1_wdt_write(struct k1_wdt *wdt, int reg, uint32_t value)
{
	writel(WDT_FIRST_ACCESS_KEY, wdt->base + WDT_FIRST_ACCESS);
	writel(WDT_SECOND_ACCESS_KEY, wdt->base + WDT_SECOND_ACCESS);
	writel(value, wdt->base + reg);
}

static inline int k1_wdt_set_timeout_ticks(struct k1_wdt *wdt,
				    unsigned int timeout_ticks)
{
	k1_wdt_write(wdt, WDT_MATCH_VALUE, timeout_ticks);

	if (k1_wdt_read(wdt, WDT_MATCH_VALUE) != timeout_ticks)
		return -EIO;

	return 0;
}

static inline int k1_wdt_set_timeout_sec(struct k1_wdt *wdt,
				  unsigned int timeout)
{
	return k1_wdt_set_timeout_ticks(wdt, WDT_TIME_TO_TICKS(timeout));
}

static int k1_wdt_ping(struct watchdog_device *wdd)
{
	struct k1_wdt *wdt = container_of(wdd, struct k1_wdt, wdd);
	int ret = 0;

	if (wdd->pretimeout && wdt->pretimeout_expired) {
		uint32_t enable = k1_wdt_read(wdt, WDT_MATCH_ENABLE);
		wdt->pretimeout_expired = false;
		ret = k1_wdt_set_timeout_sec(wdt, wdt->wdd.pretimeout);
		k1_wdt_write(wdt, WDT_MATCH_ENABLE, enable &
			     ~WDT_MATCH_EXPIRE_RESET);
	}

	k1_wdt_write(wdt, WDT_COUNTER_RESET, 1);

	return ret;
}

static int k1_wdt_start(struct watchdog_device *wdd)
{
	struct k1_wdt *wdt = container_of(wdd, struct k1_wdt, wdd);
	uint32_t enable = WDT_MATCH_EXPIRE_ENABLE;
	int ret;

	k1_wdt_write(wdt, WDT_COUNTER_RESET, 1);
	enable |= k1_wdt_read(wdt, WDT_MATCH_ENABLE);

	if (wdd->pretimeout) {
		enable &= ~WDT_MATCH_EXPIRE_RESET;
		ret = k1_wdt_set_timeout_sec(wdt, wdd->pretimeout);
	} else {
		enable |= WDT_MATCH_EXPIRE_RESET;
		ret = k1_wdt_set_timeout_sec(wdt, wdd->timeout);
	}

	if (ret) {
		dev_err(wdd->parent, "could not set timeout\n");
		return ret;
	}

	k1_wdt_write(wdt, WDT_MATCH_ENABLE, enable);

	return 0;
}

static inline int k1_wdt_stop(struct watchdog_device *wdd)
{
	struct k1_wdt *wdt = container_of(wdd, struct k1_wdt, wdd);
	uint32_t enable = k1_wdt_read(wdt, WDT_MATCH_ENABLE);

	k1_wdt_write(wdt, WDT_MATCH_ENABLE, enable & ~WDT_MATCH_EXPIRE_ENABLE);

	return 0;
}

static int k1_wdt_set_timeout(struct watchdog_device *wdd, unsigned int timeout)
{
	unsigned int prev;
	int ret = 0;

	if (watchdog_timeout_invalid(wdd, timeout))
		return -EINVAL;

	prev = wdd->timeout;
	wdd->timeout = timeout;
	if (watchdog_hw_running(wdd))
		ret = k1_wdt_start(wdd);

	if (ret) {
		wdd->timeout = prev;
		return ret;
	}

	return 0;
}

static int k1_wdt_set_pretimeout(struct watchdog_device *wdd, unsigned int pretimeout)
{
	unsigned int prev;
	int ret = 0;

	if (watchdog_pretimeout_invalid(wdd, pretimeout))
		return -EINVAL;

	prev = wdd->pretimeout;
	wdd->pretimeout = pretimeout;
	if (watchdog_hw_running(wdd))
		ret = k1_wdt_start(wdd);

	if (ret) {
		wdd->pretimeout = prev;
		return ret;
	}

	return 0;
}

static unsigned int k1_wdt_get_timeleft(struct watchdog_device *wdd)
{
	struct k1_wdt *wdt = container_of(wdd, struct k1_wdt, wdd);

	return wdd->timeout - WDT_TICKS_TO_TIME(k1_wdt_read(wdt, WDT_VALUE)
						& 0xffff);
}

static int k1_wdt_restart(struct watchdog_device *wdd, unsigned long action,
			  void *extra)
{
	struct k1_wdt *wdt = container_of(wdd, struct k1_wdt, wdd);
	int ret = 0;

	ret = k1_wdt_set_timeout_ticks(wdt, 1);
	if (ret)
		return ret;

	k1_wdt_write(wdt, WDT_MATCH_ENABLE, WDT_MATCH_EXPIRE_ENABLE |
					    WDT_MATCH_EXPIRE_RESET);
	mdelay(wdd->min_hw_heartbeat_ms+1);

	return 0;
}

static irqreturn_t k1_wdt_irq_handler(int irqnr, void *data)
{
	struct k1_wdt *wdt = data;
	uint32_t enable = WDT_MATCH_EXPIRE_RESET;

	k1_wdt_write(wdt, WDT_INTERRUPT_CLEAR, 1);
	wdt->pretimeout_expired = true;

	enable |= k1_wdt_read(wdt, WDT_MATCH_ENABLE);
	k1_wdt_set_timeout_sec(wdt, wdt->wdd.timeout - wdt->wdd.pretimeout);
	k1_wdt_write(wdt, WDT_COUNTER_RESET, 1);
	k1_wdt_write(wdt, WDT_MATCH_ENABLE, enable);

	watchdog_notify_pretimeout(&wdt->wdd);

	return IRQ_HANDLED;
}

static const struct of_device_id k1_wdt_match[] = {
	{ .compatible = "spacemit,k1-wdt", .data = NULL },
	{}
};
MODULE_DEVICE_TABLE(of, k1_wdt_match);

static const struct watchdog_ops k1_wdt_ops = {
	.owner = THIS_MODULE,
	.start = k1_wdt_start,
	.stop = k1_wdt_stop,
	.ping = k1_wdt_ping,
	.set_timeout = k1_wdt_set_timeout,
	.get_timeleft = k1_wdt_get_timeleft,
	.set_pretimeout = k1_wdt_set_pretimeout,
	.restart = k1_wdt_restart
};

static const struct watchdog_info k1_wdt_info = {
	.options = WDIOF_SETTIMEOUT | WDIOF_MAGICCLOSE | WDIOF_PRETIMEOUT |
		   WDIOF_KEEPALIVEPING,
	.identity = "SpacemiT K1 watchdog timer",
};

static int k1_wdt_probe(struct platform_device *pdev)
{
	struct k1_wdt *wdt;
	struct device *dev = &pdev->dev;
	struct watchdog_device *wdd;
	struct resource wdt_mem;

	int irq, ret;

	wdt = devm_kzalloc(dev, sizeof(*wdt), GFP_KERNEL);
	if (!wdt)
		return dev_err_probe(dev, -ENOMEM,
				     "failed to allocate memory\n");
	wdt->pdev = pdev;
	wdd = &wdt->wdd;
	wdd->info = &k1_wdt_info;
	wdd->ops = &k1_wdt_ops;
	wdd->min_timeout = 1;
	wdd->min_hw_heartbeat_ms = 1000 / WDT_TICK_RATE;
	wdd->max_hw_heartbeat_ms = WDT_TICKS_MAX * 1000 / WDT_TICK_RATE;
	wdd->parent = dev;

	watchdog_set_nowayout(wdd, nowayout);
	watchdog_set_restart_priority(wdd, SYS_OFF_PRIO_LOW);
	watchdog_stop_on_unregister(wdd);

	ret = of_address_to_resource(to_of_node(dev->fwnode), 0, &wdt_mem);
	if (ret)
		return dev_err_probe(dev, ret, "no watchdog region\n");

	wdt->base = devm_ioremap(dev, wdt_mem.start, resource_size(&wdt_mem));
	if (IS_ERR(wdt->base))
		return dev_err_probe(dev, PTR_ERR(wdt->base),
				     "failed to map watchdog registers\n");

	wdt->core_clk = devm_clk_get_enabled(dev, "core");
	if (IS_ERR(wdt->core_clk))
		return dev_err_probe(dev, PTR_ERR(wdt->core_clk),
				     "failed to get watchdog core clock\n");

	wdt->bus_clk = devm_clk_get_enabled(dev, "bus");
	if (IS_ERR(wdt->bus_clk))
		return dev_err_probe(dev, PTR_ERR(wdt->bus_clk),
				     "failed to get watchdog bus clock\n");

	wdt->reset = devm_reset_control_get_exclusive_deasserted(dev, NULL);
	if (IS_ERR(wdt->reset))
		return dev_err_probe(dev, PTR_ERR(wdt->reset),
				     "failed to get watchdog reset\n");

	/* initialize to known state */
	k1_wdt_ping(wdd);
	k1_wdt_stop(wdd);
	k1_wdt_write(wdt, WDT_INTERRUPT_CLEAR, 1);

	irq = of_irq_get(to_of_node(dev->fwnode), 0);
	irq = irq ? irq : -ENODEV;
	/* TODO: handle deferred probe */
	if (irq < 0)
		return dev_err_probe(dev, ret, "failed to map irq\n");

	ret = devm_request_irq(dev, irq, k1_wdt_irq_handler, IRQF_TRIGGER_NONE,
			       DRIVER_NAME, wdt);

	ret = watchdog_init_timeout(wdd, timeout, dev);
	if (ret)
		return ret;

	ret = k1_wdt_set_timeout(wdd, wdd->timeout);
	if (ret)
		return ret;

	ret = devm_watchdog_register_device(dev, wdd);
	if (ret)
		return ret;

	if (early_enable)
		k1_wdt_start(wdd);

	dev_info(dev, "initialized with nowayout=%d, timeout=%d, early_enable=%d\n",
		 nowayout, timeout, early_enable);
	return 0;
}

static void k1_wdt_remove(struct platform_device *pdev)
{
}

static struct platform_driver k1_wdt_driver = {
	.probe = k1_wdt_probe,
	.remove = k1_wdt_remove,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = k1_wdt_match
	}
};

module_platform_driver(k1_wdt_driver);

MODULE_DESCRIPTION("Spacemit K1 watchdog timer");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" DRIVER_NAME);
