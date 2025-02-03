// SPDX-License-Identifier: GPL-2.0
#include <asm/entry.h>
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/hardirq.h>
#include <linux/irq.h>
#include <linux/irqflags.h>
#include <linux/percpu.h>
#include <linux/rseq.h>
#include <asm/traps.h>

#include "irq.h"
#include "../mm/fault.h"

noinstr asmlinkage void arm_und_handler(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	/*
	 * IRQs must be enabled before attempting to read the instruction from
	 * user space since that could cause a page/translation fault if the
	 * page table was modified by another CPU.
	 */

	local_irq_enable();

	do_undefinstr(regs);

	local_irq_disable();

	irqentry_exit(regs, state);
}

noinstr asmlinkage void arm_dabt_handler(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();

	do_DataAbort(addr, fsr, regs);

	local_irq_disable();

	irqentry_exit(regs, state);
}

noinstr asmlinkage void arm_pabt_handler(unsigned long addr, unsigned int ifsr, struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();

	do_PrefetchAbort(addr, ifsr, regs);

	local_irq_disable();

	irqentry_exit(regs, state);
}

static void noinstr handle_arm_irq(void *data)
{
	struct pt_regs *regs = data;
	struct pt_regs *old_regs;

	irq_enter_rcu();
	old_regs = set_irq_regs(regs);

	handle_arch_irq(regs);

	set_irq_regs(old_regs);
	irq_exit_rcu();
}

noinstr void arm_irq_handler(struct pt_regs *regs, int mode)
{
	irqentry_state_t state = irqentry_enter(regs);

	/*
	 * If we are executing in kernel context and we are already on
	 * the IRQ stack (i.e. we get interrupted in interrupt context)
	 * then just handle the IRQ, else switch to the IRQ stack and
	 * handle the interrupt using the IRQ stack.
	 */
	if ((mode == 0) && on_irq_stack(regs))
		handle_arm_irq(regs);
	else
		call_on_irq_stack(handle_arm_irq, regs);

	irqentry_exit(regs, state);
}

/*
 * Handle FIQ similarly to NMI on x86 systems.
 *
 * The runtime environment for NMIs is extremely restrictive
 * (NMIs can pre-empt critical sections meaning almost all locking is
 * forbidden) meaning this default FIQ handling must only be used in
 * circumstances where non-maskability improves robustness, such as
 * watchdog or debug logic.
 *
 * This handler is not appropriate for general purpose use in drivers
 * platform code and can be overrideen using set_fiq_handler.
 */
noinstr void arm_fiq_handler(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_nmi_enter(regs);

	irqentry_nmi_exit(regs, state);
}

asmlinkage void arm_exit_to_user_mode(struct pt_regs *regs)
{
	local_irq_disable();
	irqentry_exit_to_user_mode(regs);
}
