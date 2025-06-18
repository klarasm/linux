/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_S390_BUG_H
#define _ASM_S390_BUG_H

#include <linux/compiler.h>

#ifdef CONFIG_BUG

#ifdef CONFIG_DEBUG_BUGVERBOSE

#define __EMIT_BUG(cond_str, x) do {				\
	asm_inline volatile(					\
		"0:	mc	0,0\n"				\
		".section __bug_table,\"aw\"\n"			\
		"1:	.long	0b-.\n"				\
		"	.long	%0-.\n"				\
		"	.short	%1,%2\n"			\
		"	.org	1b+%3\n"			\
		".previous\n"					\
		: : "i" (WARN_CONDITION_STR(cond_str) __FILE__),\
		    "i" (__LINE__),				\
		    "i" (x),					\
		    "i" (sizeof(struct bug_entry)));		\
} while (0)

#else /* CONFIG_DEBUG_BUGVERBOSE */

#define __EMIT_BUG(cond_str, x) do {				\
	asm_inline volatile(					\
		"0:	mc	0,0\n"				\
		".section __bug_table,\"aw\"\n"			\
		"1:	.long	0b-.\n"				\
		"	.short	%0\n"				\
		"	.org	1b+%1\n"			\
		".previous\n"					\
		: : "i" (x),					\
		    "i" (sizeof(struct bug_entry)));		\
} while (0)

#endif /* CONFIG_DEBUG_BUGVERBOSE */

#define BUG() do {					\
	__EMIT_BUG("", 0);				\
	unreachable();					\
} while (0)

#define __WARN_FLAGS(cond_str, flags) do {		\
	__EMIT_BUG(cond_str, BUGFLAG_WARNING|(flags));	\
} while (0)

#define WARN_ON(x) ({					\
	int __ret_warn_on = !!(x);			\
	if (__builtin_constant_p(__ret_warn_on)) {	\
		if (__ret_warn_on)			\
			__WARN();			\
	} else {					\
		if (unlikely(__ret_warn_on))		\
			__WARN();			\
	}						\
	unlikely(__ret_warn_on);			\
})

#define HAVE_ARCH_BUG
#define HAVE_ARCH_WARN_ON
#endif /* CONFIG_BUG */

#include <asm-generic/bug.h>

#endif /* _ASM_S390_BUG_H */
