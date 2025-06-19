// SPDX-License-Identifier: GPL-v2-only

#include <linux/printk.h>
#include <linux/dev_printk.h>
#include <linux/platform_device.h>
#include <linux/watchdog.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/container_of.h>

#include <linux/of.h>
#include <linux/of_address.h>

#define DRIVER_NAME "spacemit-k1-wdt"

#define WDT_ACCESS_A		0xb0
#define WDT_ACCESS_A_KEY	0xbaba

#define WDT_ACCESS_B		0xb4
#define WDT_ACCESS_B_KEY	0xeb10

#define WDT_MATCH_ENABLE	0xb8
#define WDT_MATCH_VALUE		0xbc

#define WDT_STATUS		0xc0
#define WDT_INTERRUPT_CLEAR	0xc4
#define WDT_COUNTER_RESET	0xc8
#define WDT_VALUE		0xcc

#define WDT_TICK_SHIFT 8
#define WDT_TICKS_TO_TIME(ticks) (ticks >> WDT_TICK_SHIFT)
#define WDT_TIME_TO_TICKS(time) (time << WDT_TICK_SHIFT)
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

static int reboot = CONFIG_SPACEMIT_K1_WATCHDOG_REBOOT;
module_param(reboot, int, 0);
MODULE_PARM_DESC(reboot, "Use the watchdog as a restart handler (default="
			  __MODULE_STRING(CONFIG_SPACEMIT_K1_WATCHDOG_REBOOT)
			  ")");

static int early_enable = WDT_EARLY_ENABLE;
module_param(early_enable, int, WDT_EARLY_ENABLE);
MODULE_PARM_DESC(early_enable, "Enable watchdog when driver is loaded (default="
			__MODULE_STRING(WDT_EARLY_ENABLE) ")");

struct k1_wdt {
	struct platform_device *pdev;
	struct watchdog_device wdt;
	struct notifier_block reboot;
	void __iomem *base;
};

static u32 k1_wdt_read(struct k1_wdt *data, int reg)
{
	return readl(data->base + reg);
}

static void k1_wdt_write(struct k1_wdt *data, int reg, u32 value)
{
	writel(WDT_ACCESS_A_KEY, data->base + WDT_ACCESS_A);
	writel(WDT_ACCESS_B_KEY, data->base + WDT_ACCESS_B);
	writel(value, data->base + reg);
}

static int k1_wdt_ping(struct watchdog_device *wdt)
{
	struct k1_wdt *data = container_of(wdt, struct k1_wdt, wdt);

	k1_wdt_write(data, WDT_COUNTER_RESET, 1);

	return 0;
}

static int k1_wdt_start(struct watchdog_device *wdt)
{
	struct k1_wdt *data = container_of(wdt, struct k1_wdt, wdt);
	int ret;

	ret = k1_wdt_ping(wdt);
	if (ret)
		return ret;

	k1_wdt_write(data, WDT_INTERRUPT_CLEAR, 1);
	k1_wdt_write(data, WDT_MATCH_ENABLE,
			BIT(0)		/* Enable matching on timer */
			| BIT(1)	/* Reset the system on match */
			);

	return 0;
}

static int k1_wdt_stop(struct watchdog_device *wdt)
{
	struct k1_wdt *data = container_of(wdt, struct k1_wdt, wdt);

	k1_wdt_write(data, WDT_MATCH_ENABLE, 0);

	return 0;
}

static int k1_wdt_timeout_ticks(struct k1_wdt *data, unsigned int timeout_ticks)
{
	k1_wdt_write(data, WDT_MATCH_VALUE, timeout_ticks);

	if (k1_wdt_read(data, WDT_MATCH_VALUE) != timeout_ticks)
		return -EIO;

	return 0;
}

static int k1_wdt_timeout(struct watchdog_device *wdt, unsigned int timeout)
{
	struct k1_wdt *data = container_of(wdt, struct k1_wdt, wdt);
	unsigned int ticks = WDT_TIME_TO_TICKS(timeout);
	int ret;

	ret = k1_wdt_timeout_ticks(data, ticks);
	if (ret)
		return ret;

	wdt->timeout = timeout;

	return 0;
}

static unsigned int k1_wdt_timeleft(struct watchdog_device *wdt)
{
	struct k1_wdt *data = container_of(wdt, struct k1_wdt, wdt);
	unsigned int ticks;

	if (k1_wdt_read(data, WDT_STATUS & 1)) {
		dev_warn(&data->pdev->dev, "watchdog timer was overrun\n");
		return 0;
	}

	ticks = k1_wdt_read(data, WDT_VALUE) & 0xffff;

	return wdt->timeout - WDT_TICKS_TO_TIME(ticks);
}

static int k1_wdt_reboot(struct notifier_block *reboot, unsigned long action,
		void *extra)
{
	struct k1_wdt *data = container_of(reboot, struct k1_wdt, reboot);

	k1_wdt_timeout_ticks(data, 1);
	k1_wdt_start(&data->wdt);
	mdelay(10);

	return 0;
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
	.set_timeout = k1_wdt_timeout,
	.get_timeleft = k1_wdt_timeleft,
};

static const struct watchdog_info k1_wdt_info = {
	.options = WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE,
	.identity = "Spacemit K1 watchdog timer",
};

static int k1_wdt_probe(struct platform_device *pdev)
{
	struct k1_wdt *data;
	struct device *dev = &pdev->dev;
	struct resource wdt_mem;

	int ret;

	data = devm_kzalloc(dev, sizeof(struct k1_wdt), GFP_KERNEL);
	if (!data)
		return dev_err_probe(dev, -ENOMEM, "failed to allocate memory\n");

	data->pdev = pdev;
	platform_set_drvdata(pdev, data);

	data->wdt.info = &k1_wdt_info;
	data->wdt.ops = &k1_wdt_ops;
	data->wdt.parent = dev;

	data->reboot.notifier_call = k1_wdt_reboot;
	data->reboot.priority = SYS_OFF_PRIO_LOW;

	watchdog_set_nowayout(&data->wdt, nowayout);

	ret = of_address_to_resource(to_of_node(dev->fwnode), 0, &wdt_mem);
	if (ret)
		return dev_err_probe(dev, ret, "no watchdog region\n");

	data->base = devm_ioremap(dev, wdt_mem.start, resource_size(&wdt_mem));
	if (IS_ERR(data->base))
		return dev_err_probe(dev, PTR_ERR(data->base),
				"failed to map watchdog registers\n");

	ret = k1_wdt_timeout(&data->wdt, timeout);
	if (ret)
		return dev_err_probe(dev, ret, "failed to set timeout\n");

	ret = k1_wdt_ping(&data->wdt);
	if (ret)
		return dev_err_probe(dev, ret, "failed to clear timer register\n");

	k1_wdt_write(data, WDT_INTERRUPT_CLEAR, 1);

	ret = devm_watchdog_register_device(dev, &data->wdt);
	if (ret)
		return dev_err_probe(dev, ret, "failed to register watchdog\n");

	if (reboot) {
		ret = register_restart_handler(&data->reboot);
		if (ret)
			dev_warn(dev, "failed to register restart handler\n");
	}

	if (early_enable) {
		ret = k1_wdt_start(&data->wdt);
		if (ret)
			return dev_err_probe(dev, ret, "failed to start watchdog early\n");
	}

	dev_info(dev, "Spacemit K1 watchdog timer\n");
	return 0;
}

static void k1_wdt_remove(struct platform_device *pdev)
{
	struct k1_wdt *data = platform_get_drvdata(pdev);

	k1_wdt_stop(&data->wdt);
	if (reboot)
		unregister_restart_handler(&data->reboot);
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
