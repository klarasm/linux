// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Yixun Lan <dlan@gentoo.org> */

#include <linux/bitfield.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/module.h>

#include <linux/pinctrl/consumer.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>

#include "../core.h"
#include "../pinctrl-utils.h"
#include "../pinconf.h"
#include "../pinmux.h"
#include "pinctrl-k1.h"

/*
 * +---------+----------+-----------+--------+--------+----------+--------+
 * |   pull  |   drive  | schmitter |  slew  |  edge  |  strong  |   mux  |
 * | up/down | strength |  trigger  |  rate  | detect |   pull   |  mode  |
 * +---------+----------+-----------+--------+--------+----------+--------+
 *   3 bits     3 bits     2 bits     1 bit    3 bits     1 bit    3 bits
 */

#define PAD_MUX			GENMASK(2, 0)
#define PAD_STRONG_PULL		BIT(3)
#define PAD_EDGE_RISE		BIT(4)
#define PAD_EDGE_FALL		BIT(5)
#define PAD_EDGE_CLEAR		BIT(6)
#define PAD_SLEW_RATE		GENMASK(12, 11)
#define PAD_SLEW_RATE_EN	BIT(7)
#define PAD_SCHMITT		GENMASK(9, 8)
#define PAD_DRIVE		GENMASK(12, 10)
#define PAD_PULLDOWN		BIT(13)
#define PAD_PULLUP		BIT(14)
#define PAD_PULL_EN		BIT(15)

#define spacemit_pin_to_reg(pctrl, pin)		((pctrl)->regs + (pin << 2))

struct spacemit_pin {
	u16				pin;
	u16				flags;
	u8				gpiofunc;
};

struct spacemit_pinctrl {
	struct device				*dev;
	struct pinctrl_dev			*pctl_dev;
	const struct spacemit_pinctrl_data	*data;
	struct pinctrl_desc			pdesc;

	struct mutex				mutex;
	raw_spinlock_t				lock;

	void __iomem				*regs;
};

struct spacemit_pinctrl_data {
	const struct pinctrl_pin_desc   *pins;
	const struct spacemit_pin	*data;
	u16				npins;
};

struct spacemit_pin_mux_config {
	const struct spacemit_pin	*pin;
	u32		config;
};

struct spacemit_pin_drv_strength {
	u8		val;
	u32		mA;
};

static unsigned int spacemit_dt_get_pin(u32 value)
{
	return (value >> 16) & GENMASK(15, 0);
}

static unsigned int spacemit_dt_get_pin_mux(u32 value)
{
	return value & GENMASK(15, 0);
}

static const struct spacemit_pin *spacemit_get_pin(struct spacemit_pinctrl *pctrl,
						   unsigned long pin)
{
	const struct spacemit_pin *pdata = pctrl->data->data;
	int i;

	for (i = 0; i < pctrl->data->npins; i++) {
		if (pin == pdata[i].pin)
			return &pdata[i];
	}

	return NULL;
}

static inline enum spacemit_pin_io_type spacemit_to_pin_io_type(
	const struct spacemit_pin *pin)
{
	return K1_PIN_GET_IO_TYPE(pin->flags);
}

/* External: IO voltage via external source, can be 1.8V or 3.3V */
static const char * const io_type_desc[] = {
	"None",
	"Fixed/1V8",
	"Fixed/3V3",
	"External",
};

static void spacemit_pctrl_dbg_show(struct pinctrl_dev *pctldev,
				    struct seq_file *seq, unsigned int pin)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	const struct spacemit_pin *spin = spacemit_get_pin(pctrl, pin);
	enum spacemit_pin_io_type type = spacemit_to_pin_io_type(spin);
	void __iomem *reg;
	u32 value;

	seq_printf(seq, "pin: %u ", spin->pin);

	seq_printf(seq, "type: %s ", io_type_desc[type]);

	reg = spacemit_pin_to_reg(pctrl, spin->pin);
	value = readl(reg);
	seq_printf(seq, "mux: %ld reg: 0x%04x", (value & PAD_MUX), value);
}

/* use IO high level output current as the table */
static struct spacemit_pin_drv_strength spacemit_ds_1v8_tbl[4] = {
	{ 0, 11 },
	{ 2, 21 },
	{ 4, 32 },
	{ 6, 42 },
};

static struct spacemit_pin_drv_strength spacemit_ds_3v3_tbl[8] = {
	{ 0,  7 },
	{ 2, 10 },
	{ 4, 13 },
	{ 6, 16 },
	{ 1, 19 },
	{ 3, 23 },
	{ 5, 26 },
	{ 7, 29 },
};

static inline u8 spacemit_get_ds_value(struct spacemit_pin_drv_strength *tbl,
				       u32 num, u32 mA)
{
	int i;

	for (i = 0; i < num; i++)
		if (mA <= tbl[i].mA)
			return tbl[i].val;

	return tbl[num - 1].val;
}

static inline u8 spacemit_get_driver_strength(enum spacemit_pin_io_type type,
					      u32 mA)
{
	switch (type) {
	case IO_TYPE_1V8:
		return spacemit_get_ds_value(spacemit_ds_1v8_tbl,
					     ARRAY_SIZE(spacemit_ds_1v8_tbl),
					     mA);
	case IO_TYPE_3V3:
		return spacemit_get_ds_value(spacemit_ds_3v3_tbl,
					     ARRAY_SIZE(spacemit_ds_3v3_tbl),
					     mA);
	default:
		return 0;
	}
}
static int spacemit_pctrl_check_power(struct pinctrl_dev *pctldev,
				      struct device_node *dn,
				      struct spacemit_pin_mux_config *pinmuxs,
				      int num_pins, const char *grpname)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	struct device *dev = pctrl->dev;
	enum spacemit_pin_io_type type;
	u32 power = 0, i;

	of_property_read_u32(dn, "power-source", &power);

	for (i = 0; i < num_pins; i++) {
		type = spacemit_to_pin_io_type(pinmuxs[i].pin);

		if (type != IO_TYPE_EXTERNAL)
			continue;

		switch (power) {
		case PIN_POWER_STATE_1V8:
		case PIN_POWER_STATE_3V3:
			break;
		default:
			dev_err(dev, "group %s has unsupported power\n",
				grpname);
			return -ENOTSUPP;
		}
	}

	return 0;
}

static int spacemit_pctrl_dt_node_to_map(struct pinctrl_dev *pctldev,
					 struct device_node *np,
					 struct pinctrl_map **maps,
					 unsigned int *num_maps)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	struct device *dev = pctrl->dev;
	struct device_node *child;
	struct pinctrl_map *map;
	const char **grpnames;
	const char *grpname;
	int ngroups = 0;
	int nmaps = 0;
	int ret;

	for_each_available_child_of_node(np, child)
		ngroups += 1;

	grpnames = devm_kcalloc(dev, ngroups, sizeof(*grpnames), GFP_KERNEL);
	if (!grpnames)
		return -ENOMEM;

	map = devm_kcalloc(dev, ngroups * 2, sizeof(*map), GFP_KERNEL);
	if (!map)
		return -ENOMEM;

	ngroups = 0;
	mutex_lock(&pctrl->mutex);
	for_each_available_child_of_node(np, child) {
		int npins = of_property_count_u32_elems(child, "pinmux");
		unsigned int *pins;
		struct spacemit_pin_mux_config *pinmuxs;
		u32 config;
		int i;

		if (npins < 1) {
			dev_err(dev, "invalid pinctrl group %pOFn.%pOFn\n",
				np, child);
			ret = -EINVAL;
			goto dt_failed;
		}

		grpname = devm_kasprintf(dev, GFP_KERNEL, "%pOFn.%pOFn",
					 np, child);
		if (!grpname) {
			ret = -ENOMEM;
			goto dt_failed;
		}

		grpnames[ngroups++] = grpname;

		pins = devm_kcalloc(dev, npins, sizeof(*pins), GFP_KERNEL);
		if (!pins) {
			ret = -ENOMEM;
			goto dt_failed;
		}

		pinmuxs = devm_kcalloc(dev, npins, sizeof(*pinmuxs), GFP_KERNEL);
		if (!pinmuxs) {
			ret = -ENOMEM;
			goto dt_failed;
		}

		for (i = 0; i < npins; i++) {
			ret = of_property_read_u32_index(child, "pinmux",
							 i, &config);

			if (ret)
				goto dt_failed;

			pins[i] = spacemit_dt_get_pin(config);
			pinmuxs[i].config = config;
			pinmuxs[i].pin = spacemit_get_pin(pctrl, pins[i]);

			if (!pinmuxs[i].pin) {
				dev_err(dev, "failed to get pin %d\n", pins[i]);
				ret = -ENODEV;
				goto dt_failed;
			}
		}

		ret = spacemit_pctrl_check_power(pctldev, child, pinmuxs,
						 npins, grpname);
		if (ret < 0)
			goto dt_failed;

		map[nmaps].type = PIN_MAP_TYPE_MUX_GROUP;
		map[nmaps].data.mux.function = np->name;
		map[nmaps].data.mux.group = grpname;
		nmaps += 1;

		ret = pinctrl_generic_add_group(pctldev, grpname,
						pins, npins, pinmuxs);
		if (ret < 0) {
			dev_err(dev, "failed to add group %s: %d\n", grpname, ret);
			goto dt_failed;
		}

		ret = pinconf_generic_parse_dt_config(child, pctldev,
						      &map[nmaps].data.configs.configs,
						      &map[nmaps].data.configs.num_configs);
		if (ret) {
			dev_err(dev, "failed to parse pin config of group %s: %d\n",
				grpname, ret);
			goto dt_failed;
		}

		if (map[nmaps].data.configs.num_configs == 0)
			continue;

		map[nmaps].type = PIN_MAP_TYPE_CONFIGS_GROUP;
		map[nmaps].data.configs.group_or_pin = grpname;
		nmaps += 1;
	}

	ret = pinmux_generic_add_function(pctldev, np->name,
					  grpnames, ngroups, NULL);
	if (ret < 0) {
		dev_err(dev, "error adding function %s: %d\n", np->name, ret);
		goto function_failed;
	}

	*maps = map;
	*num_maps = nmaps;
	mutex_unlock(&pctrl->mutex);

	return 0;

dt_failed:
	of_node_put(child);
function_failed:
	pinctrl_utils_free_map(pctldev, map, nmaps);
	mutex_unlock(&pctrl->mutex);
	return ret;
}

static const struct pinctrl_ops spacemit_pctrl_ops = {
	.get_groups_count	= pinctrl_generic_get_group_count,
	.get_group_name		= pinctrl_generic_get_group_name,
	.get_group_pins		= pinctrl_generic_get_group_pins,
	.pin_dbg_show		= spacemit_pctrl_dbg_show,
	.dt_node_to_map		= spacemit_pctrl_dt_node_to_map,
	.dt_free_map		= pinctrl_utils_free_map,
};

static int spacemit_pmx_set_mux(struct pinctrl_dev *pctldev,
			      unsigned int fsel, unsigned int gsel)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	const struct group_desc *group;
	const struct spacemit_pin_mux_config *configs;
	unsigned int i, mux;
	void __iomem *reg;

	group = pinctrl_generic_get_group(pctldev, gsel);
	if (!group)
		return -EINVAL;

	configs = group->data;

	for (i = 0; i < group->grp.npins; i++) {
		const struct spacemit_pin *spin = configs[i].pin;
		u32 value = configs[i].config;
		unsigned long flags;

		reg = spacemit_pin_to_reg(pctrl, spin->pin);
		mux = spacemit_dt_get_pin_mux(value);

		raw_spin_lock_irqsave(&pctrl->lock, flags);
		value = readl_relaxed(reg) & ~PAD_MUX;
		writel_relaxed(mux | value, reg);
		raw_spin_unlock_irqrestore(&pctrl->lock, flags);
	}

	return 0;
}

static int spacemit_request_gpio(struct pinctrl_dev *pctldev,
				 struct pinctrl_gpio_range *range,
				 unsigned int pin)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	const struct spacemit_pin *spin = spacemit_get_pin(pctrl, pin);
	void __iomem *reg;

	reg = spacemit_pin_to_reg(pctrl, pin);
	writel(spin->gpiofunc, reg);

	return 0;
}

static const struct pinmux_ops spacemit_pmx_ops = {
	.get_functions_count	= pinmux_generic_get_function_count,
	.get_function_name	= pinmux_generic_get_function_name,
	.get_function_groups	= pinmux_generic_get_function_groups,
	.set_mux		= spacemit_pmx_set_mux,
	.gpio_request_enable	= spacemit_request_gpio,
	.strict			= true,
};

static int spacemit_pinconf_get(struct pinctrl_dev *pctldev,
				unsigned int pin, unsigned long *config)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	int param = pinconf_to_config_param(*config);
	u32 value, arg;

	if (!pin)
		return -EINVAL;

	value = readl(spacemit_pin_to_reg(pctrl, pin));

	switch (param) {
	case PIN_CONFIG_BIAS_DISABLE:
		arg = !FIELD_GET(PAD_PULL_EN, value);
		break;
	case PIN_CONFIG_BIAS_PULL_DOWN:
		arg = FIELD_GET(PAD_PULLDOWN, value);
		break;
	case PIN_CONFIG_BIAS_PULL_UP:
		arg = FIELD_GET(PAD_PULLUP, value);
		break;
	case PIN_CONFIG_DRIVE_STRENGTH:
		arg = FIELD_GET(PAD_DRIVE, value);
		break;
	case PIN_CONFIG_INPUT_SCHMITT:
		arg = FIELD_GET(PAD_SCHMITT, value);
		break;
	case PIN_CONFIG_SLEW_RATE:
		arg = FIELD_GET(PAD_SLEW_RATE, value);
		break;
	default:
		return -EINVAL;
	}

	*config = pinconf_to_config_packed(param, arg);

	return 0;
}

#define ENABLE_DRV_STRENGTH	BIT(1)
#define ENABLE_SLEW_RATE	BIT(2)
static int spacemit_pinconf_generate_config(const struct spacemit_pin *spin,
					    unsigned long *configs,
					    unsigned int num_configs,
					    u32 *value)
{
	enum spacemit_pin_io_type type;
	int i, param;
	u32 v = 0, voltage = 0, arg, val;
	u32 flag = 0, drv_strength, slew_rate;

	if (!spin)
		return -EINVAL;

	for (i = 0; i < num_configs; i++) {
		param = pinconf_to_config_param(configs[i]);
		arg = pinconf_to_config_argument(configs[i]);

		switch (param) {
		case PIN_CONFIG_BIAS_DISABLE:
			v &= ~(PAD_PULL_EN | PAD_PULLDOWN | PAD_PULLUP);
			v &= ~PAD_STRONG_PULL;
			break;
		case PIN_CONFIG_BIAS_PULL_DOWN:
			v &= ~(PAD_PULLUP | PAD_STRONG_PULL);
			v |= (PAD_PULL_EN | PAD_PULLDOWN);
			break;
		case PIN_CONFIG_BIAS_PULL_UP:
			v &= ~PAD_PULLDOWN;
			v |= (PAD_PULL_EN | PAD_PULLUP);

			if (arg == 1)
				v |= PAD_STRONG_PULL;
			break;
		case PIN_CONFIG_DRIVE_STRENGTH:
			flag |= ENABLE_DRV_STRENGTH;
			drv_strength = arg;
			break;
		case PIN_CONFIG_INPUT_SCHMITT:
			v &= ~PAD_SCHMITT;
			v |= FIELD_PREP(PAD_SCHMITT, arg);
			break;
		case PIN_CONFIG_POWER_SOURCE:
			voltage = arg;
			break;
		case PIN_CONFIG_SLEW_RATE:
			if (arg) {
				flag |= ENABLE_SLEW_RATE;
				v |= PAD_SLEW_RATE_EN;
				slew_rate = arg;
			} else {
				v &= ~PAD_SLEW_RATE_EN;
			}
			break;
		default:
			return -EINVAL;
		}
	}

	if (flag & ENABLE_DRV_STRENGTH) {
		type = spacemit_to_pin_io_type(spin);

		/* fix external io type */
		if (type == IO_TYPE_EXTERNAL) {
			switch (voltage) {
			case 1800:
				type = IO_TYPE_1V8;
				break;
			case 3300:
				type = IO_TYPE_3V3;
				break;
			default:
				return -EINVAL;
			}
		}

		val = spacemit_get_driver_strength(type, drv_strength);

		v &= ~PAD_DRIVE;
		v |= FIELD_PREP(PAD_DRIVE, val);
	}

	if (flag & ENABLE_SLEW_RATE) {
		/* check, driver strength & slew rate */
		if (flag & ENABLE_DRV_STRENGTH) {
			val = FIELD_GET(PAD_SLEW_RATE, v) + 2;
			if (slew_rate > 1 && slew_rate != val) {
				pr_err("slew rate conflict with drive strength\n");
				return -EINVAL;
			}
		} else {
			v &= ~PAD_SLEW_RATE;
			slew_rate = slew_rate > 1 ? (slew_rate - 2) : 0;
			v |= FIELD_PREP(PAD_SLEW_RATE, slew_rate);
		}
	}

	*value = v;

	return 0;
}

static int spacemit_pin_set_config(struct spacemit_pinctrl *pctrl,
				 unsigned int pin,
				 u32 value)
{
	const struct spacemit_pin *spin = spacemit_get_pin(pctrl, pin);
	void __iomem *reg;
	unsigned long flags;
	unsigned int mux;

	if (!pin)
		return -EINVAL;

	reg = spacemit_pin_to_reg(pctrl, spin->pin);

	raw_spin_lock_irqsave(&pctrl->lock, flags);
	mux = readl_relaxed(reg) & PAD_MUX;
	writel_relaxed(mux | value, reg);
	raw_spin_unlock_irqrestore(&pctrl->lock, flags);

	return 0;
}

static int spacemit_pinconf_set(struct pinctrl_dev *pctldev,
				unsigned int pin, unsigned long *configs,
				unsigned int num_configs)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	const struct spacemit_pin *spin = spacemit_get_pin(pctrl, pin);
	u32 value;

	if (spacemit_pinconf_generate_config(spin, configs, num_configs, &value))
		return -EINVAL;

	return spacemit_pin_set_config(pctrl, pin, value);
}

static int spacemit_pinconf_group_set(struct pinctrl_dev *pctldev,
				      unsigned int gsel,
				      unsigned long *configs,
				      unsigned int num_configs)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	const struct spacemit_pin *spin;
	const struct group_desc *group;
	u32 value;
	int i;

	group = pinctrl_generic_get_group(pctldev, gsel);
	if (!group)
		return -EINVAL;

	spin = spacemit_get_pin(pctrl, group->grp.pins[0]);
	if (spacemit_pinconf_generate_config(spin, configs, num_configs, &value))
		return -EINVAL;

	for (i = 0; i < group->grp.npins; i++)
		spacemit_pin_set_config(pctrl, group->grp.pins[i], value);

	return 0;
}

static void spacemit_pinconf_dbg_show(struct pinctrl_dev *pctldev,
				      struct seq_file *seq, unsigned int pin)
{
	struct spacemit_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	const struct spacemit_pin *spin = spacemit_get_pin(pctrl, pin);
	enum spacemit_pin_io_type type = spacemit_to_pin_io_type(spin);
	void __iomem *reg;
	u32 value;

	reg = spacemit_pin_to_reg(pctrl, pin);
	value = readl(reg);
	seq_printf(seq, ", io type (%d)", type);
	seq_printf(seq, ", strong pull (%ld)", FIELD_GET(PAD_STRONG_PULL, value));
	seq_printf(seq, ", register (0x%04x)\n", value);
}

static const struct pinconf_ops spacemit_pinconf_ops = {
	.pin_config_get			= spacemit_pinconf_get,
	.pin_config_set			= spacemit_pinconf_set,
	.pin_config_group_set		= spacemit_pinconf_group_set,
	.pin_config_dbg_show		= spacemit_pinconf_dbg_show,
	.is_generic			= true,
};

static int spacemit_pinctrl_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct spacemit_pinctrl *pctrl;
	const struct spacemit_pinctrl_data *pctrl_data;
	int ret;

	pctrl_data = device_get_match_data(dev);
	if (!pctrl_data)
		return -ENODEV;

	if (pctrl_data->npins == 0)
		return dev_err_probe(dev, -EINVAL, "invalid pin data\n");

	pctrl = devm_kzalloc(dev, sizeof(*pctrl), GFP_KERNEL);
	if (!pctrl)
		return -ENOMEM;

	pctrl->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(pctrl->regs))
		return PTR_ERR(pctrl->regs);

	pctrl->pdesc.name = dev_name(dev);
	pctrl->pdesc.pins = pctrl_data->pins;
	pctrl->pdesc.npins = pctrl_data->npins;
	pctrl->pdesc.pctlops = &spacemit_pctrl_ops;
	pctrl->pdesc.pmxops = &spacemit_pmx_ops;
	pctrl->pdesc.confops = &spacemit_pinconf_ops;
	pctrl->pdesc.owner = THIS_MODULE;

	pctrl->data = pctrl_data;
	pctrl->dev = dev;
	raw_spin_lock_init(&pctrl->lock);
	mutex_init(&pctrl->mutex);

	platform_set_drvdata(pdev, pctrl);

	ret = devm_pinctrl_register_and_init(dev, &pctrl->pdesc,
					     pctrl, &pctrl->pctl_dev);
	if (ret)
		return dev_err_probe(dev, ret,
				     "fail to register pinctrl driver\n");

	return pinctrl_enable(pctrl->pctl_dev);
}

static const struct pinctrl_pin_desc k1_pin_desc[] = {
	PINCTRL_PIN(GPIO_00, "GPIO_00"),
	PINCTRL_PIN(GPIO_01, "GPIO_01"),
	PINCTRL_PIN(GPIO_02, "GPIO_02"),
	PINCTRL_PIN(GPIO_03, "GPIO_03"),
	PINCTRL_PIN(GPIO_04, "GPIO_04"),
	PINCTRL_PIN(GPIO_05, "GPIO_05"),
	PINCTRL_PIN(GPIO_06, "GPIO_06"),
	PINCTRL_PIN(GPIO_07, "GPIO_07"),
	PINCTRL_PIN(GPIO_08, "GPIO_08"),
	PINCTRL_PIN(GPIO_09, "GPIO_09"),
	PINCTRL_PIN(GPIO_10, "GPIO_10"),
	PINCTRL_PIN(GPIO_11, "GPIO_11"),
	PINCTRL_PIN(GPIO_12, "GPIO_12"),
	PINCTRL_PIN(GPIO_13, "GPIO_13"),
	PINCTRL_PIN(GPIO_14, "GPIO_14"),
	PINCTRL_PIN(GPIO_15, "GPIO_15"),
	PINCTRL_PIN(GPIO_16, "GPIO_16"),
	PINCTRL_PIN(GPIO_17, "GPIO_17"),
	PINCTRL_PIN(GPIO_18, "GPIO_18"),
	PINCTRL_PIN(GPIO_19, "GPIO_19"),
	PINCTRL_PIN(GPIO_20, "GPIO_20"),
	PINCTRL_PIN(GPIO_21, "GPIO_21"),
	PINCTRL_PIN(GPIO_22, "GPIO_22"),
	PINCTRL_PIN(GPIO_23, "GPIO_23"),
	PINCTRL_PIN(GPIO_24, "GPIO_24"),
	PINCTRL_PIN(GPIO_25, "GPIO_25"),
	PINCTRL_PIN(GPIO_26, "GPIO_26"),
	PINCTRL_PIN(GPIO_27, "GPIO_27"),
	PINCTRL_PIN(GPIO_28, "GPIO_28"),
	PINCTRL_PIN(GPIO_29, "GPIO_29"),
	PINCTRL_PIN(GPIO_30, "GPIO_30"),
	PINCTRL_PIN(GPIO_31, "GPIO_31"),
	PINCTRL_PIN(GPIO_32, "GPIO_32"),
	PINCTRL_PIN(GPIO_33, "GPIO_33"),
	PINCTRL_PIN(GPIO_34, "GPIO_34"),
	PINCTRL_PIN(GPIO_35, "GPIO_35"),
	PINCTRL_PIN(GPIO_36, "GPIO_36"),
	PINCTRL_PIN(GPIO_37, "GPIO_37"),
	PINCTRL_PIN(GPIO_38, "GPIO_38"),
	PINCTRL_PIN(GPIO_39, "GPIO_39"),
	PINCTRL_PIN(GPIO_40, "GPIO_40"),
	PINCTRL_PIN(GPIO_41, "GPIO_41"),
	PINCTRL_PIN(GPIO_42, "GPIO_42"),
	PINCTRL_PIN(GPIO_43, "GPIO_43"),
	PINCTRL_PIN(GPIO_44, "GPIO_44"),
	PINCTRL_PIN(GPIO_45, "GPIO_45"),
	PINCTRL_PIN(GPIO_46, "GPIO_46"),
	PINCTRL_PIN(GPIO_47, "GPIO_47"),
	PINCTRL_PIN(GPIO_48, "GPIO_48"),
	PINCTRL_PIN(GPIO_49, "GPIO_49"),
	PINCTRL_PIN(GPIO_50, "GPIO_50"),
	PINCTRL_PIN(GPIO_51, "GPIO_51"),
	PINCTRL_PIN(GPIO_52, "GPIO_52"),
	PINCTRL_PIN(GPIO_53, "GPIO_53"),
	PINCTRL_PIN(GPIO_54, "GPIO_54"),
	PINCTRL_PIN(GPIO_55, "GPIO_55"),
	PINCTRL_PIN(GPIO_56, "GPIO_56"),
	PINCTRL_PIN(GPIO_57, "GPIO_57"),
	PINCTRL_PIN(GPIO_58, "GPIO_58"),
	PINCTRL_PIN(GPIO_59, "GPIO_59"),
	PINCTRL_PIN(GPIO_60, "GPIO_60"),
	PINCTRL_PIN(GPIO_61, "GPIO_61"),
	PINCTRL_PIN(GPIO_62, "GPIO_62"),
	PINCTRL_PIN(GPIO_63, "GPIO_63"),
	PINCTRL_PIN(GPIO_64, "GPIO_64"),
	PINCTRL_PIN(GPIO_65, "GPIO_65"),
	PINCTRL_PIN(GPIO_66, "GPIO_66"),
	PINCTRL_PIN(GPIO_67, "GPIO_67"),
	PINCTRL_PIN(GPIO_68, "GPIO_68"),
	PINCTRL_PIN(GPIO_69, "GPIO_69"),
	PINCTRL_PIN(GPIO_70, "GPIO_70/PRI_DTI"),
	PINCTRL_PIN(GPIO_71, "GPIO_71/PRI_TMS"),
	PINCTRL_PIN(GPIO_72, "GPIO_72/PRI_TCK"),
	PINCTRL_PIN(GPIO_73, "GPIO_73/PRI_TDO"),
	PINCTRL_PIN(GPIO_74, "GPIO_74"),
	PINCTRL_PIN(GPIO_75, "GPIO_75"),
	PINCTRL_PIN(GPIO_76, "GPIO_76"),
	PINCTRL_PIN(GPIO_77, "GPIO_77"),
	PINCTRL_PIN(GPIO_78, "GPIO_78"),
	PINCTRL_PIN(GPIO_79, "GPIO_79"),
	PINCTRL_PIN(GPIO_80, "GPIO_80"),
	PINCTRL_PIN(GPIO_81, "GPIO_81"),
	PINCTRL_PIN(GPIO_82, "GPIO_82"),
	PINCTRL_PIN(GPIO_83, "GPIO_83"),
	PINCTRL_PIN(GPIO_84, "GPIO_84"),
	PINCTRL_PIN(GPIO_85, "GPIO_85"),
	PINCTRL_PIN(GPIO_86, "GPIO_86"),
	PINCTRL_PIN(GPIO_87, "GPIO_87"),
	PINCTRL_PIN(GPIO_88, "GPIO_88"),
	PINCTRL_PIN(GPIO_89, "GPIO_89"),
	PINCTRL_PIN(GPIO_90, "GPIO_90"),
	PINCTRL_PIN(GPIO_91, "GPIO_91"),
	PINCTRL_PIN(GPIO_92, "GPIO_92"),
	PINCTRL_PIN(GPIO_93, "GPIO_93/PWR_SCL"),
	PINCTRL_PIN(GPIO_94, "GPIO_94/PWR_SDA"),
	PINCTRL_PIN(GPIO_95, "GPIO_95/VCX0_EN"),
	PINCTRL_PIN(GPIO_96, "GPIO_96/DVL0"),
	PINCTRL_PIN(GPIO_97, "GPIO_97/DVL1"),
	PINCTRL_PIN(GPIO_98,  "GPIO_98/QSPI_DAT3"),
	PINCTRL_PIN(GPIO_99,  "GPIO_99/QSPI_DAT2"),
	PINCTRL_PIN(GPIO_100, "GPIO_100/QSPI_DAT1"),
	PINCTRL_PIN(GPIO_101, "GPIO_101/QSPI_DAT0"),
	PINCTRL_PIN(GPIO_102, "GPIO_102/QSPI_CLK"),
	PINCTRL_PIN(GPIO_103, "GPIO_103/QSPI_CSI"),
	PINCTRL_PIN(GPIO_104, "GPIO_104/MMC1_DAT3"),
	PINCTRL_PIN(GPIO_105, "GPIO_105/MMC1_DAT2"),
	PINCTRL_PIN(GPIO_106, "GPIO_106/MMC1_DAT1"),
	PINCTRL_PIN(GPIO_107, "GPIO_107/MMC1_DAT0"),
	PINCTRL_PIN(GPIO_108, "GPIO_108/MMC1_CMD"),
	PINCTRL_PIN(GPIO_109, "GPIO_109/MMC1_CLK"),
	PINCTRL_PIN(GPIO_110, "GPIO_110"),
	PINCTRL_PIN(GPIO_111, "GPIO_111"),
	PINCTRL_PIN(GPIO_112, "GPIO_112"),
	PINCTRL_PIN(GPIO_113, "GPIO_113"),
	PINCTRL_PIN(GPIO_114, "GPIO_114"),
	PINCTRL_PIN(GPIO_115, "GPIO_115"),
	PINCTRL_PIN(GPIO_116, "GPIO_116"),
	PINCTRL_PIN(GPIO_117, "GPIO_117"),
	PINCTRL_PIN(GPIO_118, "GPIO_118"),
	PINCTRL_PIN(GPIO_119, "GPIO_119"),
	PINCTRL_PIN(GPIO_120, "GPIO_120"),
	PINCTRL_PIN(GPIO_121, "GPIO_121"),
	PINCTRL_PIN(GPIO_122, "GPIO_122"),
	PINCTRL_PIN(GPIO_123, "GPIO_123"),
	PINCTRL_PIN(GPIO_124, "GPIO_124"),
	PINCTRL_PIN(GPIO_125, "GPIO_125"),
	PINCTRL_PIN(GPIO_126, "GPIO_126"),
	PINCTRL_PIN(GPIO_127, "GPIO_127"),
};

static const struct spacemit_pin k1_pin_data[ARRAY_SIZE(k1_pin_desc)] = {
	K1_FUNC_PIN(GPIO_00, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_01, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_02, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_03, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_04, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_05, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_06, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_07, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_08, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_09, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_10, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_11, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_12, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_13, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_14, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_15, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_16, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_17, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_18, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_19, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_20, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_21, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_22, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_23, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_24, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_25, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_26, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_27, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_28, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_29, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_30, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_31, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_32, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_33, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_34, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_35, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_36, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_37, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_38, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_39, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_40, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_41, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_42, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_43, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_44, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_45, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_46, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_47, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_48, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_49, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_50, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_51, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_52, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_53, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_54, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_55, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_56, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_57, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_58, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_59, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_60, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_61, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_62, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_63, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_64, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_65, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_66, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_67, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_68, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_69, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_70, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_71, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_72, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_73, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_74, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_75, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_76, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_77, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_78, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_79, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_80, 0, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_81, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_82, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_83, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_84, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_85, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_86, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_87, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_88, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_89, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_90, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_91, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_92, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_93, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_94, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_95, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_96, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_97, 1, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_98, 1, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_99, 1, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_100, 1, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_101, 1, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_102, 1, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_103, 1, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_104, 4, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_105, 4, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_106, 4, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_107, 4, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_108, 4, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_109, 4, IO_TYPE_EXTERNAL),
	K1_FUNC_PIN(GPIO_110, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_111, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_112, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_113, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_114, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_115, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_116, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_117, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_118, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_119, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_120, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_121, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_122, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_123, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_124, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_125, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_126, 0, IO_TYPE_1V8),
	K1_FUNC_PIN(GPIO_127, 0, IO_TYPE_1V8),
};

static const struct spacemit_pinctrl_data k1_pinctrl_data = {
	.pins = k1_pin_desc,
	.data = k1_pin_data,
	.npins = ARRAY_SIZE(k1_pin_desc),
};

static const struct of_device_id k1_pinctrl_ids[] = {
	{ .compatible = "spacemit,k1-pinctrl", .data = &k1_pinctrl_data },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, k1_pinctrl_ids);

static struct platform_driver k1_pinctrl_driver = {
	.probe	= spacemit_pinctrl_probe,
	.driver	= {
		.name			= "k1-pinctrl",
		.suppress_bind_attrs	= true,
		.of_match_table		= k1_pinctrl_ids,
	},
};
module_platform_driver(k1_pinctrl_driver);

MODULE_AUTHOR("Yixun Lan <dlan@gentoo.org>");
MODULE_DESCRIPTION("Pinctrl driver for the SpacemiT K1 SoC");
MODULE_LICENSE("GPL");
