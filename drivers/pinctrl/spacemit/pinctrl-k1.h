/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024 Yixun Lan <dlan@gentoo.org> */

#ifndef _PINCTRL_SPACEMIT_K1_H
#define _PINCTRL_SPACEMIT_K1_H

#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinconf.h>

enum spacemit_pin_io_type {
	IO_TYPE_NONE = 0,
	IO_TYPE_1V8,
	IO_TYPE_3V3,
	IO_TYPE_EXTERNAL,
};

#define PIN_POWER_STATE_1V8		1800
#define PIN_POWER_STATE_3V3		3300

#define K1_PIN_IO_TYPE		GENMASK(2, 1)

#define K1_PIN_CAP_IO_TYPE(type)				\
	FIELD_PREP_CONST(K1_PIN_IO_TYPE, type)
#define K1_PIN_GET_IO_TYPE(val)					\
	FIELD_GET(K1_PIN_IO_TYPE, val)

#define K1_FUNC_PIN(_id, _gpiofunc, _io)			\
	{							\
		.pin		= (_id),			\
		.gpiofunc	= (_gpiofunc),			\
		.flags		= (K1_PIN_CAP_IO_TYPE(_io)),	\
	}

/* pin offset */
#define PINID(x)	((x) + 1)

#define GPIO_INVAL  0
#define GPIO_00     PINID(0)
#define GPIO_01     PINID(1)
#define GPIO_02     PINID(2)
#define GPIO_03     PINID(3)
#define GPIO_04     PINID(4)
#define GPIO_05     PINID(5)
#define GPIO_06     PINID(6)
#define GPIO_07     PINID(7)
#define GPIO_08     PINID(8)
#define GPIO_09     PINID(9)
#define GPIO_10     PINID(10)
#define GPIO_11     PINID(11)
#define GPIO_12     PINID(12)
#define GPIO_13     PINID(13)
#define GPIO_14     PINID(14)
#define GPIO_15     PINID(15)
#define GPIO_16     PINID(16)
#define GPIO_17     PINID(17)
#define GPIO_18     PINID(18)
#define GPIO_19     PINID(19)
#define GPIO_20     PINID(20)
#define GPIO_21     PINID(21)
#define GPIO_22     PINID(22)
#define GPIO_23     PINID(23)
#define GPIO_24     PINID(24)
#define GPIO_25     PINID(25)
#define GPIO_26     PINID(26)
#define GPIO_27     PINID(27)
#define GPIO_28     PINID(28)
#define GPIO_29     PINID(29)
#define GPIO_30     PINID(30)
#define GPIO_31     PINID(31)

#define GPIO_32     PINID(32)
#define GPIO_33     PINID(33)
#define GPIO_34     PINID(34)
#define GPIO_35     PINID(35)
#define GPIO_36     PINID(36)
#define GPIO_37     PINID(37)
#define GPIO_38     PINID(38)
#define GPIO_39     PINID(39)
#define GPIO_40     PINID(40)
#define GPIO_41     PINID(41)
#define GPIO_42     PINID(42)
#define GPIO_43     PINID(43)
#define GPIO_44     PINID(44)
#define GPIO_45     PINID(45)
#define GPIO_46     PINID(46)
#define GPIO_47     PINID(47)
#define GPIO_48     PINID(48)
#define GPIO_49     PINID(49)
#define GPIO_50     PINID(50)
#define GPIO_51     PINID(51)
#define GPIO_52     PINID(52)
#define GPIO_53     PINID(53)
#define GPIO_54     PINID(54)
#define GPIO_55     PINID(55)
#define GPIO_56     PINID(56)
#define GPIO_57     PINID(57)
#define GPIO_58     PINID(58)
#define GPIO_59     PINID(59)
#define GPIO_60     PINID(60)
#define GPIO_61     PINID(61)
#define GPIO_62     PINID(62)
#define GPIO_63     PINID(63)

#define GPIO_64     PINID(64)
#define GPIO_65     PINID(65)
#define GPIO_66     PINID(66)
#define GPIO_67     PINID(67)
#define GPIO_68     PINID(68)
#define GPIO_69     PINID(69)
#define GPIO_70     PINID(70)
#define GPIO_71     PINID(71)
#define GPIO_72     PINID(72)
#define GPIO_73     PINID(73)
#define GPIO_74     PINID(74)
#define GPIO_75     PINID(75)
#define GPIO_76     PINID(76)
#define GPIO_77     PINID(77)
#define GPIO_78     PINID(78)
#define GPIO_79     PINID(79)
#define GPIO_80     PINID(80)
#define GPIO_81     PINID(81)
#define GPIO_82     PINID(82)
#define GPIO_83     PINID(83)
#define GPIO_84     PINID(84)
#define GPIO_85     PINID(85)

#define GPIO_101    PINID(89)
#define GPIO_100    PINID(90)
#define GPIO_99     PINID(91)
#define GPIO_98     PINID(92)
#define GPIO_103    PINID(93)
#define GPIO_102    PINID(94)

#define GPIO_104    PINID(109)
#define GPIO_105    PINID(110)
#define GPIO_106    PINID(111)
#define GPIO_107    PINID(112)
#define GPIO_108    PINID(113)
#define GPIO_109    PINID(114)
#define GPIO_110    PINID(115)

#define GPIO_93     PINID(116)
#define GPIO_94     PINID(117)
#define GPIO_95     PINID(118)
#define GPIO_96     PINID(119)
#define GPIO_97     PINID(120)

#define GPIO_86     PINID(122)
#define GPIO_87     PINID(123)
#define GPIO_88     PINID(124)
#define GPIO_89     PINID(125)
#define GPIO_90     PINID(126)
#define GPIO_91     PINID(127)
#define GPIO_92     PINID(128)

#define GPIO_111    PINID(130)
#define GPIO_112    PINID(131)
#define GPIO_113    PINID(132)
#define GPIO_114    PINID(133)
#define GPIO_115    PINID(134)
#define GPIO_116    PINID(135)
#define GPIO_117    PINID(136)
#define GPIO_118    PINID(137)
#define GPIO_119    PINID(138)
#define GPIO_120    PINID(139)
#define GPIO_121    PINID(140)
#define GPIO_122    PINID(141)
#define GPIO_123    PINID(142)
#define GPIO_124    PINID(143)
#define GPIO_125    PINID(144)
#define GPIO_126    PINID(145)
#define GPIO_127    PINID(146)

#endif /* _PINCTRL_SPACEMIT_K1_H */
