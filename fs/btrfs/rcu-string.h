/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2012 Red Hat.  All rights reserved.
 */

#ifndef BTRFS_RCU_STRING_H
#define BTRFS_RCU_STRING_H

#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/printk.h>

struct rcu_string {
	struct rcu_head rcu;
	char str[];
};

static inline struct rcu_string *rcu_string_strdup(const char *src, gfp_t mask)
{
	size_t len = strlen(src) + 1;
	struct rcu_string *ret = kzalloc(sizeof(struct rcu_string) +
					 (len * sizeof(char)), mask);
	if (!ret)
		return ret;
	/* Warn if the source got unexpectedly truncated. */
	if (WARN_ON(strscpy(ret->str, src, len) < 0)) {
		kfree(ret);
		return NULL;
	}
	return ret;
}

#define rcu_str_deref(rcu_str) ({				\
	struct rcu_string *__str = rcu_dereference(rcu_str);	\
	__str->str;						\
})

#endif
