/*
 * Copyright (c) 2017-2018, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) "xive-kvm: " fmt

#include <linux/anon_inodes.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <asm/uaccess.h>
#include <asm/kvm_book3s.h>
#include <asm/kvm_ppc.h>
#include <asm/hvcall.h>
#include <asm/xics.h>
#include <asm/xive.h>
#include <asm/xive-regs.h>
#include <asm/debug.h>
#include <asm/debugfs.h>
#include <asm/time.h>
#include <asm/opal.h>

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "book3s_xive.h"

/*
 * We still instanciate them here because we use some of the
 * generated utility functions as well in this file.
 */
#define XIVE_RUNTIME_CHECKS
#define X_PFX xive_vm_
#define X_STATIC static
#define X_STAT_PFX stat_vm_
#define __x_tima		xive_tima
#define __x_eoi_page(xd)	((void __iomem *)((xd)->eoi_mmio))
#define __x_trig_page(xd)	((void __iomem *)((xd)->trig_mmio))
#define __x_writeb	__raw_writeb
#define __x_readw	__raw_readw
#define __x_readq	__raw_readq
#define __x_writeq	__raw_writeq

#include "book3s_xive_native_template.c"

static void xive_native_cleanup_queue(struct kvm_vcpu *vcpu, int prio)
{
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	struct xive_q *q = &xc->queues[prio];

	xive_native_disable_queue(xc->vp_id, q, prio);
	if (q->qpage) {
		put_page(virt_to_page(q->qpage));
		q->qpage = NULL;
	}
}

int kvmppc_xive_native_cleanup_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	int i;

	pr_devel("native_cleanup_vcpu(cpu=%d)\n", xc->server_num);

	if (!kvmppc_xive_enabled(vcpu))
		return -EPERM;

	if (!xc)
		return -ENOENT;

	/* Ensure no interrupt is still routed to that VP */
	xc->valid = false;
	kvmppc_xive_disable_vcpu_interrupts(vcpu);

	/* Disable the VP */
	xive_native_disable_vp(xc->vp_id);

	/* Free the queues & associated interrupts */
	for (i = 0; i < KVMPPC_XIVE_Q_COUNT; i++) {
		/* Free the escalation irq */
		if (xc->esc_virq[i]) {
			free_irq(xc->esc_virq[i], vcpu);
			irq_dispose_mapping(xc->esc_virq[i]);
			kfree(xc->esc_virq_names[i]);
			xc->esc_virq[i] = 0;
		}

		/* Free the queue */
		xive_native_cleanup_queue(vcpu, i);
	}

	/* Free the VP */
	kfree(xc);

	/* Cleanup the vcpu */
	vcpu->arch.irq_type = KVMPPC_IRQ_DEFAULT;
	vcpu->arch.xive_vcpu = NULL;
	return 0;
}

int kvmppc_xive_native_connect_vcpu(struct kvm_device *dev,
				    struct kvm_vcpu *vcpu, u32 cpu)
{
	struct kvmppc_xive *xive = dev->private;
	struct kvmppc_xive_vcpu *xc;
	int rc;

	pr_devel("native_connect_vcpu(cpu=%d)\n", cpu);

	if (dev->ops != &kvm_xive_native_ops) {
		pr_devel("Wrong ops !\n");
		return -EPERM;
	}
	if (xive->kvm != vcpu->kvm)
		return -EPERM;
	if (vcpu->arch.irq_type)
		return -EBUSY;
	if (kvmppc_xive_find_server(vcpu->kvm, cpu)) {
		pr_devel("Duplicate !\n");
		return -EEXIST;
	}
	if (cpu >= KVM_MAX_VCPUS) {
		pr_devel("Out of bounds !\n");
		return -EINVAL;
	}
	xc = kzalloc(sizeof(*xc), GFP_KERNEL);
	if (!xc)
		return -ENOMEM;

	mutex_lock(&vcpu->kvm->lock);
	vcpu->arch.xive_vcpu = xc;
	xc->xive = xive;
	xc->vcpu = vcpu;
	xc->server_num = cpu;
	xc->vp_id = xive->vp_base + cpu;
	xc->valid = true;

	rc = xive_native_get_vp_info(xc->vp_id, &xc->vp_cam, &xc->vp_chip_id);
	if (rc) {
		pr_err("Failed to get VP info from OPAL: %d\n", rc);
		goto bail;
	}

	/*
	 * Enable the VP first as the single escalation mode will
	 * affect escalation interrupts numbering
	 */
	rc = xive_native_enable_vp(xc->vp_id, xive->single_escalation);
	if (rc) {
		pr_err("Failed to enable VP in OPAL: %d\n", rc);
		goto bail;
	}

	/* Configure VCPU fields for use by assembly push/pull */
	vcpu->arch.xive_saved_state.w01 = cpu_to_be64(0xff000000);
	vcpu->arch.xive_cam_word = cpu_to_be32(xc->vp_cam | TM_QW1W2_VO);

	/* TODO: reset queues ? */

bail:
	vcpu->arch.irq_type = KVMPPC_IRQ_XIVE;
	mutex_unlock(&vcpu->kvm->lock);
	if (rc)
		kvmppc_xive_native_cleanup_vcpu(vcpu);

	return rc;
}

static int xive_native_validate_queue_size(u32 qsize)
{
	switch (qsize) {
	case 12:
	case 16:
	case 21:
	case 24:
	case 0:
		return 0;
	default:
		return -EINVAL;
	}
}

int kvmppc_xive_get_vp(struct kvm_vcpu *vcpu, union kvmppc_one_reg *val)
{
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	u32 version;
	int rc;

	if (!kvmppc_xive_enabled(vcpu))
		return -EPERM;

	if (!xc)
		return -ENOENT;

	val->xive_timaval[0] = vcpu->arch.xive_saved_state.w01;

	rc = xive_native_get_vp_state(xc->vp_id, &version, &val->xive_timaval[1]);
	if (rc)
		return rc;

	/* For QEMU monitor */
	val->xive_timaval[2] = vcpu->arch.xive_cam_word;

	if (XIVE_STATE_COMPAT(version) > 1) {
		pr_err("invalid OPAL state version %08x\n", version);
		return -EIO;
	}

	pr_devel("%s NSR=%02x CPPR=%02x IBP=%02x PIPR=%02x w01=%016llx w2=%08x opal=%016llx\n",
		 __func__,
		 vcpu->arch.xive_saved_state.nsr,
		 vcpu->arch.xive_saved_state.cppr,
		 vcpu->arch.xive_saved_state.ipb,
		 vcpu->arch.xive_saved_state.pipr,
		 vcpu->arch.xive_saved_state.w01,
		 (u32) vcpu->arch.xive_cam_word, val->xive_timaval[1]);

	return 0;
}

int kvmppc_xive_set_vp(struct kvm_vcpu *vcpu, union kvmppc_one_reg *val)
{
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	u32 version = XIVE_STATE_VERSION;
	int rc;

	pr_devel("%s w01=%016llx vp=%016llx\n", __func__, val->xive_timaval[0],
		 val->xive_timaval[1]);

	if (!kvmppc_xive_enabled(vcpu))
		return -EPERM;

	if (!xc || !xive)
		return -ENOENT;

	/* We can't update the state of a "pushed" VCPU	 */
	if (WARN_ON(vcpu->arch.xive_pushed))
		return -EIO;

	/* TODO: only restore IPB and CPPR ? */
	vcpu->arch.xive_saved_state.w01 = val->xive_timaval[0];

	rc = xive_native_set_vp_state(xc->vp_id, version, val->xive_timaval[1]);
	if (rc)
		return rc;

	return 0;
}

int kvmppc_xive_get_vp_queue(struct kvm_vcpu *vcpu, int priority,
			     union kvmppc_one_reg *val)
{
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	struct xive_q *q;
	u64 qpage;
	u64 qsize;
	u64 qeoi_page;
	u32 escalate_irq;
	u64 qflags;
	u32 version;
	u64 qw1;
	int rc;

	pr_debug("%s vcpu %d priority %d\n", __func__, xc->server_num,
		 priority);

	if (!kvmppc_xive_enabled(vcpu))
		return -EPERM;

	if (!xc)
		return -ENOENT;

	if (priority != xive_prio_from_guest(priority) || priority == MASKED) {
		pr_err("Trying to retrieve info from queue %d for VCPU %d\n",
		       priority, xc->server_num);
		return -EINVAL;
	}
	q = &xc->queues[priority];

	memset(val->xive_eqval, 0, sizeof(val->xive_eqval));

	if (!q->qpage)
		return 0;

	rc = xive_native_get_queue_info(xc->vp_id, priority, &qpage, &qsize,
					&qeoi_page, &escalate_irq, &qflags);
	if (rc)
		return rc;

	rc = xive_native_get_queue_state(xc->vp_id, priority, &version, &qw1);
	if (rc)
		return rc;

	if (XIVE_STATE_COMPAT(version) > 1) {
		pr_err("invalid OPAL state version %08x\n", version);
		return -EIO;
	}

	val->xive_eqval[0] = 0;
	if (qflags & OPAL_XIVE_EQ_ENABLED)
		val->xive_eqval[0] |= EQ_W0_VALID|EQ_W0_ENQUEUE;
	if (qflags & OPAL_XIVE_EQ_ALWAYS_NOTIFY)
		val->xive_eqval[0] |= EQ_W0_UCOND_NOTIFY;
	if (qflags & OPAL_XIVE_EQ_ESCALATE)
		val->xive_eqval[0] |= EQ_W0_ESCALATE_CTL;
	val->xive_eqval[0] |= SETFIELD(EQ_W0_QSIZE, 0ul, qsize - 12);

	val->xive_eqval[1] = qw1 & 0xffffffff;
	val->xive_eqval[2] = (q->guest_qpage >> 32) & 0x0fffffff;
	val->xive_eqval[3] = q->guest_qpage & 0xffffffff;
	val->xive_eqval[4] = 0;
	val->xive_eqval[5] = 0;
	val->xive_eqval[6] = SETFIELD(EQ_W6_NVT_BLOCK, 0ul, 0ul) |
		SETFIELD(EQ_W6_NVT_INDEX, 0ul, xc->server_num);
	val->xive_eqval[7] = SETFIELD(EQ_W7_F0_PRIORITY, 0ul, priority);

	/* Mark EQ page dirty for migration */
	mark_page_dirty(vcpu->kvm, gpa_to_gfn(q->guest_qpage));

	return 0;
}

int kvmppc_xive_set_vp_queue(struct kvm_vcpu *vcpu, int priority,
			     union kvmppc_one_reg *val)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	u32 qsize;
	u64 qpage;
	u32 server;
	u8 prio;
	int rc;
	__be32 *qaddr = 0;
	struct page *page;
	struct xive_q *q;
	u32 version = XIVE_STATE_VERSION;

	pr_devel("%s VCPU %d priority %d\n", __func__, xc->server_num,
		 priority);

	if (!xc || !xive)
		return -ENOENT;

	/*
	 * Check that we are not trying to configure queues reserved
	 * for the hypervisor
	 */
	if (priority != xive_prio_from_guest(priority) || priority == MASKED) {
		pr_err("Trying to restore invalid queue %d for VCPU %d\n",
		       priority, xc->server_num);
		return -EINVAL;
	}

	qsize = GETFIELD(EQ_W0_QSIZE, val->xive_eqval[0]) + 12;
	qpage = (((u64)(val->xive_eqval[2] & 0x0fffffff)) << 32) | val->xive_eqval[3];
	server = GETFIELD(EQ_W6_NVT_INDEX, val->xive_eqval[6]);
	prio = GETFIELD(EQ_W7_F0_PRIORITY, val->xive_eqval[7]);

	/*
	 * TODO: should we support restoring another VCPU EQs ?
	 * probably not. we should move the service at the KVM XIVE
	 * device level
	 */
	if (xc->server_num != server) {
		vcpu = kvmppc_xive_find_server(kvm, server);
		if (!vcpu) {
			pr_debug("Can't find server %d\n", server);
			return -EINVAL;
		}
		xc = vcpu->arch.xive_vcpu;
	}

	/* Sanity check */
	if (priority != prio) {
		pr_err("invalid state for queue %d for VCPU %d\n",
		       priority, xc->server_num);
		return -EIO;
	}
	q = &xc->queues[priority];

	rc = xive_native_validate_queue_size(qsize);
	if (rc || !qsize) {
		pr_err("invalid queue size %d\n", qsize);
		return rc;
	}

	page = gfn_to_page(kvm, gpa_to_gfn(qpage));
	if (is_error_page(page)) {
		pr_debug("Couldn't get guest page for %llx!\n", qpage);
		return -ENOMEM;
	}
	qaddr = page_to_virt(page) + (qpage & ~PAGE_MASK);
	q->guest_qpage = qpage;

	rc = xive_native_configure_queue(xc->vp_id, q, priority,
					 (__be32 *) qaddr, qsize, true);
	if (rc) {
		pr_err("Failed to configure queue %d for VCPU %d: %d\n",
		       priority, xc->server_num, rc);
		put_page(page);
		return rc;
	}

	rc = xive_native_set_queue_state(xc->vp_id, priority, version,
					 val->xive_eqval[1]);
	if (rc)
		goto error;

	rc = kvmppc_xive_attach_escalation(vcpu, priority);
error:
	if (rc)
		xive_native_cleanup_queue(vcpu, priority);
	return rc;
}


static int kvmppc_xive_native_set_source(struct kvmppc_xive *xive, long irq,
					 u64 addr)
{
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	u64 __user *ubufp = (u64 __user *) addr;
	u64 val;
	u16 idx;

	pr_devel("%s irq=0x%lx\n", __func__, irq);

	if (irq < KVMPPC_XIVE_FIRST_IRQ || irq >= KVMPPC_XIVE_NR_IRQS)
		return -ENOENT;

	sb = kvmppc_xive_find_source(xive, irq, &idx);
	if (!sb) {
		pr_debug("No source, creating source block...\n");
		sb = kvmppc_xive_create_src_block(xive, irq);
		if (!sb) {
			pr_err("Failed to create block...\n");
			return -ENOMEM;
		}
	}
	state = &sb->irq_state[idx];

	if (get_user(val, ubufp)) {
		pr_err("fault getting user info !\n");
		return -EFAULT;
	}

	/*
	 * If the source doesn't already have an IPI, allocate
	 * one and get the corresponding data
	 */
	if (!state->ipi_number) {
		state->ipi_number = xive_native_alloc_irq();
		if (state->ipi_number == 0) {
			pr_err("Failed to allocate IRQ !\n");
			return -ENOMEM;
		}
		xive_native_populate_irq_data(state->ipi_number,
					      &state->ipi_data);
		pr_debug("%s allocated hw_irq=0x%x for irq=0x%lx\n", __func__,
			 state->ipi_number, irq);
	}

	arch_spin_lock(&sb->lock);

	/* Restore LSI state */
	if (val & KVM_XIVE_LEVEL_SENSITIVE) {
		state->lsi = true;
		if (val & KVM_XIVE_LEVEL_ASSERTED)
			state->asserted = true;
		pr_devel("  LSI ! Asserted=%d\n", state->asserted);
	}

	/* Mask IRQ to start with */
	state->act_server = 0;
	state->act_priority = MASKED;
	xive_vm_esb_load(&state->ipi_data, XIVE_ESB_SET_PQ_01);
	xive_native_configure_irq(state->ipi_number, 0, MASKED, 0);

	/* Increment the number of valid sources and mark this one valid */
	if (!state->valid)
		xive->src_count++;
	state->valid = true;

	arch_spin_unlock(&sb->lock);

	return 0;
}

static int kvmppc_xive_native_set_vc_base(struct kvmppc_xive *xive, u64 addr)
{
	u64 __user *ubufp = (u64 __user *) addr;

	if (get_user(xive->vc_base, ubufp))
		return -EFAULT;
	return 0;
}

static int kvmppc_xive_native_get_vc_base(struct kvmppc_xive *xive, u64 addr)
{
	u64 __user *ubufp = (u64 __user *) addr;

	if (put_user(xive->vc_base, ubufp))
		return -EFAULT;

	return 0;
}

static int kvmppc_xive_native_set_source_config(struct kvmppc_xive *xive,
					struct kvmppc_xive_src_block *sb,
					struct kvmppc_xive_irq_state *state,
					u32 server,
					u8 priority,
					u32 eisn)
{
	struct kvm *kvm = xive->kvm;
	u32 hw_num;
	int rc = 0;

	/*
	 * TODO: This might be too simplistic when compared to
	 * kvmppc_xive_set_xive(). Should we do something similar to
	 * safely mask and unmask a source ? or should we just let the
	 * guest handle the possible races ?
	 */
	arch_spin_lock(&sb->lock);

	if (state->act_server == server && state->act_priority == priority &&
	    state->eisn == eisn)
		goto unlock;

	pr_devel("new_act_prio=%d new_act_server=%d act_server=%d act_prio=%d\n",
		 priority, server, state->act_server, state->act_priority);

	kvmppc_xive_select_irq(state, &hw_num, NULL);

	if (priority != MASKED) {
		rc = kvmppc_xive_select_target(kvm, &server, priority);
		if (rc)
			goto unlock;

		state->act_priority = priority;
		state->act_server = server;
		state->eisn = eisn;

		rc = xive_native_configure_irq(hw_num, xive->vp_base + server,
					       priority, eisn);
	} else {
		state->act_priority = MASKED;
		state->act_server = 0;
		state->eisn = 0;

		rc = xive_native_configure_irq(hw_num, 0, MASKED, 0);
	}

unlock:
	arch_spin_unlock(&sb->lock);
	return rc;
}

static int kvmppc_xive_native_set_ive(struct kvmppc_xive *xive, long irq,
				      u64 addr)
{
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	u64 __user *ubufp = (u64 __user *) addr;
	u16 src;
	u64 ive;
	u32 eq_idx;
	u32 server;
	u8 priority;
	u32 eisn;

	pr_devel("%s irq=0x%lx\n", __func__, irq);

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb)
		return -ENOENT;

	state = &sb->irq_state[src];

	if (!state->valid)
		return -ENOENT;

	if (get_user(ive, ubufp)) {
		pr_err("fault getting user info !\n");
		return -EFAULT;
	}

	if (!(ive & IVE_VALID) || ive & IVE_MASKED) {
		pr_err("invalid IVE %016llx for IRQ %lx\n", ive, irq);
		return -EPERM;
	}

	/* QEMU encoding of EQ index */
	eq_idx = GETFIELD(IVE_EQ_INDEX, ive);
	server = eq_idx >> 3;
	priority = eq_idx & 0x7;

	eisn = GETFIELD(IVE_EQ_DATA, ive);

	return kvmppc_xive_native_set_source_config(xive, sb, state, server,
						    priority, eisn);
}

static int kvmppc_xive_native_get_ive(struct kvmppc_xive *xive, long irq,
				      u64 addr)
{
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	u64 __user *ubufp = (u64 __user *) addr;
	u16 src;
	u64 ive;
	u32 eq_idx;

	pr_devel("%s irq=0x%lx\n", __func__, irq);

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb)
		return -ENOENT;

	state = &sb->irq_state[src];

	if (!state->valid)
		return -ENOENT;

	ive = IVE_VALID;

	arch_spin_lock(&sb->lock);

	if (state->act_priority == MASKED)
		ive |= IVE_MASKED;
	else {
		/* QEMU encoding of EQ index */
		eq_idx = ((state->act_server) << 3) |
			((state->act_priority) & 0x7);
		ive |= SETFIELD(IVE_EQ_BLOCK, 0ul, 0ul) |
			SETFIELD(IVE_EQ_INDEX, 0ul, eq_idx) |
			SETFIELD(IVE_EQ_DATA, 0ul, state->eisn);
	}
	arch_spin_unlock(&sb->lock);

	if (put_user(ive, ubufp))
		return -EFAULT;

	return 0;
}

static int kvmppc_xive_native_sync(struct kvmppc_xive *xive, long irq, u64 addr)
{
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	struct xive_irq_data *xd;
	u32 hw_num;
	u16 src;

	pr_devel("%s irq=0x%lx\n", __func__, irq);

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb)
		return -ENOENT;

	state = &sb->irq_state[src];

	if (!state->valid)
		return -ENOENT;

	arch_spin_lock(&sb->lock);

	kvmppc_xive_select_irq(state, &hw_num, &xd);
	xive_native_sync_source(hw_num);

	arch_spin_unlock(&sb->lock);
	return 0;
}

static int kvmppc_xive_native_reset_mapped(struct kvm *kvm, unsigned long irq)
{
	struct kvmppc_xive *xive = kvm->arch.xive;
	struct mm_struct *mm = kvm->mm;
	struct vm_area_struct *vma = xive->vma;
	unsigned long address;

	if (irq >= KVMPPC_XIVE_NR_IRQS)
		return -EINVAL;

	pr_debug("clearing esb pages for girq 0x%lx\n", irq);

	down_read(&mm->mmap_sem);
	/* TODO: can we clear the vma without keeping a pointer */
	if (vma) {
		address = vma->vm_start + irq * (2ull << PAGE_SHIFT);
		zap_vma_ptes(vma, address, 2ull << PAGE_SHIFT);
	}
	up_read(&mm->mmap_sem);
	return 0;
}

static struct kvmppc_xive_ops kvmppc_xive_native_ops =  {
	.reset_mapped = kvmppc_xive_native_reset_mapped,
};

static int xive_native_esb_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct kvmppc_xive *xive = vma->vm_file->private_data;
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	struct xive_irq_data *xd;
	u32 hw_num;
	u16 src;
	u64 page;
	unsigned long irq;

	/* Linux/KVM uses a two pages ESB setting, one for trigger and
	 * one for EOI */
	irq = vmf->pgoff / 2;

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb) {
		pr_err("%s: source %lx not found !\n", __func__, irq);
		return VM_FAULT_SIGBUS;
	}

	state = &sb->irq_state[src];
	kvmppc_xive_select_irq(state, &hw_num, &xd);

	arch_spin_lock(&sb->lock);

	/*
	 * first/even page is for trigger
	 * second/odd page is for EOI and management.
	 */
	page = vmf->pgoff % 2 ? xd->eoi_page : xd->trig_page;
	arch_spin_unlock(&sb->lock);

	if (!page) {
		pr_err("%s: acessing invalid ESB page for source %lx !\n",
		       __func__, irq);
		return VM_FAULT_SIGBUS;
	}

	vm_insert_pfn(vma, vmf->address, page >> PAGE_SHIFT);
	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct xive_native_esb_vmops = {
	.fault = xive_native_esb_fault,
};

static int xive_native_esb_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kvmppc_xive *xive = vma->vm_file->private_data;

	/* There are two ESB pages (trigger and EOI) per IRQ */
	if (vma_pages(vma) + vma->vm_pgoff > KVMPPC_XIVE_NR_IRQS * 2)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_ops = &xive_native_esb_vmops;
	xive->vma = vma; /* TODO: yurk yurk yurk */
	return 0;
}

static const struct file_operations xive_native_esb_fops = {
	.mmap = xive_native_esb_mmap,
};

static int kvmppc_xive_native_get_esb_fd(struct kvmppc_xive *xive, u64 addr)
{
	u64 __user *ubufp = (u64 __user *) addr;
	int ret;

	ret = anon_inode_getfd("[xive-esb]", &xive_native_esb_fops, xive,
				O_RDWR | O_CLOEXEC);
	if (ret < 0)
		return ret;

	return put_user(ret, ubufp);
}

static int xive_native_tima_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;

	switch (vmf->pgoff) {
	case 0: /* HW - forbid access */
	case 1: /* HV - forbid access */
		return VM_FAULT_SIGBUS;
	case 2: /* OS */
		vm_insert_pfn(vma, vmf->address, xive_tima_os >> PAGE_SHIFT);
		return VM_FAULT_NOPAGE;
	case 3: /* USER - TODO */
	default:
		return VM_FAULT_SIGBUS;
	}
}

static const struct vm_operations_struct xive_native_tima_vmops = {
	.fault = xive_native_tima_fault,
};

static int xive_native_tima_mmap(struct file *file, struct vm_area_struct *vma)
{
	/*
	 * The TIMA is four pages wide but only the last two pages (OS
	 * and User view) are accessible to the guest. The page fault
	 * handler will handle the permissions.
	 */
	if (vma_pages(vma) + vma->vm_pgoff > 4)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached_wc(vma->vm_page_prot);
	vma->vm_ops = &xive_native_tima_vmops;
	return 0;
}

static const struct file_operations xive_native_tima_fops = {
	.mmap = xive_native_tima_mmap,
};

static int kvmppc_xive_native_get_tima_fd(struct kvmppc_xive *xive, u64 addr)
{
	u64 __user *ubufp = (u64 __user *) addr;
	int ret;

	ret = anon_inode_getfd("[xive-tima]", &xive_native_tima_fops, xive,
			       O_RDWR | O_CLOEXEC);
	if (ret < 0)
		return ret;

	return put_user(ret, ubufp);
}

static int kvmppc_xive_native_set_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	struct kvmppc_xive *xive = dev->private;

	switch (attr->group) {
	case KVM_DEV_XIVE_GRP_SOURCES:
		return kvmppc_xive_native_set_source(xive, attr->attr,
						     attr->addr);
	case KVM_DEV_XIVE_GRP_IVE:
		return kvmppc_xive_native_set_ive(xive, attr->attr, attr->addr);
	case KVM_DEV_XIVE_GRP_SYNC:
		return kvmppc_xive_native_sync(xive, attr->attr, attr->addr);
	case KVM_DEV_XIVE_GRP_CTRL:
		switch (attr->attr) {
		case KVM_DEV_XIVE_VC_BASE:
			return kvmppc_xive_native_set_vc_base(xive, attr->addr);
		}
		break;
	}
	return -ENXIO;
}

static int kvmppc_xive_native_get_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	struct kvmppc_xive *xive = dev->private;

	switch (attr->group) {
	case KVM_DEV_XIVE_GRP_IVE:
		return kvmppc_xive_native_get_ive(xive, attr->attr, attr->addr);
	case KVM_DEV_XIVE_GRP_CTRL:
		switch (attr->attr) {
		case KVM_DEV_XIVE_GET_ESB_FD:
			return kvmppc_xive_native_get_esb_fd(xive, attr->addr);
		case KVM_DEV_XIVE_GET_TIMA_FD:
			return kvmppc_xive_native_get_tima_fd(xive, attr->addr);
		case KVM_DEV_XIVE_VC_BASE:
			return kvmppc_xive_native_get_vc_base(xive, attr->addr);
		}
		break;
	}
	return -ENXIO;
}

static int kvmppc_xive_native_has_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_DEV_XIVE_GRP_SOURCES:
	case KVM_DEV_XIVE_GRP_IVE:
	case KVM_DEV_XIVE_GRP_SYNC:
		if (attr->attr >= KVMPPC_XIVE_FIRST_IRQ &&
		    attr->attr < KVMPPC_XIVE_NR_IRQS)
			return 0;
		break;
	case KVM_DEV_XIVE_GRP_CTRL:
		switch (attr->attr) {
		case KVM_DEV_XIVE_GET_ESB_FD:
		case KVM_DEV_XIVE_GET_TIMA_FD:
		case KVM_DEV_XIVE_VC_BASE:
			return 0;
		}
		break;
	}
	return -ENXIO;
}

static void kvmppc_xive_native_free(struct kvm_device *dev)
{
	struct kvmppc_xive *xive = dev->private;
	struct kvm *kvm = xive->kvm;
	int i;

	debugfs_remove(xive->dentry);

	pr_devel("Destroying xive native for partition\n");

	if (kvm)
		kvm->arch.xive = NULL;

	/* Mask and free interrupts */
	for (i = 0; i <= xive->max_sbid; i++) {
		if (xive->src_blocks[i])
			kvmppc_xive_free_sources(xive->src_blocks[i]);
		kfree(xive->src_blocks[i]);
		xive->src_blocks[i] = NULL;
	}

	if (xive->vp_base != XIVE_INVALID_VP)
		xive_native_free_vp_block(xive->vp_base);

	kfree(xive);
	kfree(dev);
}

/*
 * ESB MMIO address of chip 0
 */
#define XIVE_VC_BASE   0x0006010000000000ull

static int kvmppc_xive_native_create(struct kvm_device *dev, u32 type)
{
	struct kvmppc_xive *xive;
	struct kvm *kvm = dev->kvm;
	int ret = 0;

	pr_devel("Creating xive native for partition\n");

	if (kvm->arch.xive)
		return -EEXIST;

	xive = kzalloc(sizeof(*xive), GFP_KERNEL);
	if (!xive)
		return -ENOMEM;

	dev->private = xive;
	xive->dev = dev;
	xive->kvm = kvm;
	kvm->arch.xive = xive;

	/* We use the default queue size set by the host */
	xive->q_order = xive_native_default_eq_shift();
	if (xive->q_order < PAGE_SHIFT)
		xive->q_page_order = 0;
	else
		xive->q_page_order = xive->q_order - PAGE_SHIFT;

	/* Allocate a bunch of VPs */
	xive->vp_base = xive_native_alloc_vp_block(KVM_MAX_VCPUS);
	pr_devel("VP_Base=%x\n", xive->vp_base);

	if (xive->vp_base == XIVE_INVALID_VP)
		ret = -ENOMEM;

	xive->vc_base = XIVE_VC_BASE;

	xive->single_escalation = xive_native_has_single_escalation();
	xive->ops = &kvmppc_xive_native_ops;

	if (ret)
		kfree(xive);

	return ret;
}

static int kvmppc_h_int_set_source_config(struct kvm_vcpu *vcpu,
					  unsigned long flags,
					  unsigned long irq,
					  unsigned long server,
					  unsigned long priority,
					  unsigned long eisn)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	int rc = 0;
	u16 idx;

	pr_devel("H_INT_SET_SOURCE_CONFIG flags=%08lx irq=%lx server=%ld priority=%ld eisn=%lx\n",
		 flags, irq, server, priority, eisn);

	if (flags & ~(XIVE_SPAPR_SRC_SET_EISN | XIVE_SPAPR_SRC_MASK))
		return H_PARAMETER;

	sb = kvmppc_xive_find_source(xive, irq, &idx);
	if (!sb)
		return H_P2;
	state = &sb->irq_state[idx];

	if (!(flags & XIVE_SPAPR_SRC_SET_EISN))
		eisn = state->eisn;

	if (priority != xive_prio_from_guest(priority)) {
		pr_err("invalid priority for queue %ld for VCPU %ld\n",
		       priority, server);
		return H_P3;
	}

	rc = kvmppc_xive_native_set_source_config(xive, sb, state, server,
						  priority, eisn);
	if (!rc)
		return H_SUCCESS;
	else if (rc == -EINVAL)
		return H_P4; /* no server found */
	else
		return H_HARDWARE;
}

static int kvmppc_h_int_set_queue_config(struct kvm_vcpu *vcpu,
					 unsigned long flags,
					 unsigned long server,
					 unsigned long priority,
					 unsigned long qpage,
					 unsigned long qsize)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	struct xive_q *q;
	int rc;
	__be32 *qaddr = 0;
	struct page *page;

	pr_devel("H_INT_SET_QUEUE_CONFIG flags=%08lx server=%ld priority=%ld qpage=%08lx qsize=%ld\n",
		 flags, server, priority, qpage, qsize);

	if (flags & ~XIVE_SPAPR_EQ_ALWAYS_NOTIFY)
		return H_PARAMETER;

	if (xc->server_num != server) {
		vcpu = kvmppc_xive_find_server(kvm, server);
		if (!vcpu) {
			pr_debug("Can't find server %ld\n", server);
			return H_P2;
		}
		xc = vcpu->arch.xive_vcpu;
	}

	if (priority != xive_prio_from_guest(priority) || priority == MASKED) {
		pr_err("invalid priority for queue %ld for VCPU %d\n",
		       priority, xc->server_num);
		return H_P3;
	}
	q = &xc->queues[priority];

	rc = xive_native_validate_queue_size(qsize);
	if (rc) {
		pr_err("invalid queue size %ld\n", qsize);
		return H_P5;
	}

	/* reset queue and disable queueing */
	if (!qsize) {
		rc = xive_native_configure_queue(xc->vp_id, q, priority,
						 NULL, 0, true);
		if (rc) {
			pr_err("Failed to reset queue %ld for VCPU %d: %d\n",
			       priority, xc->server_num, rc);
			return H_HARDWARE;
		}

		if (q->qpage) {
			put_page(virt_to_page(q->qpage));
			q->qpage = NULL;
		}

		return H_SUCCESS;
	}

	page = gfn_to_page(kvm, gpa_to_gfn(qpage));
	if (is_error_page(page)) {
		pr_warn("Couldn't get guest page for %lx!\n", qpage);
		return H_P4;
	}
	qaddr = page_to_virt(page) + (qpage & ~PAGE_MASK);

	/* Backup queue page guest address for migration */
	q->guest_qpage = qpage;

	rc = xive_native_configure_queue(xc->vp_id, q, priority,
					 (__be32 *) qaddr, qsize, true);
	if (rc) {
		pr_err("Failed to configure queue %ld for VCPU %d: %d\n",
		       priority, xc->server_num, rc);
		put_page(page);
		return H_HARDWARE;
	}

	rc = kvmppc_xive_attach_escalation(vcpu, priority);
	if (rc) {
		xive_native_cleanup_queue(vcpu, priority);
		return H_HARDWARE;
	}

	return H_SUCCESS;
}

static void kvmppc_xive_reset_sources(struct kvmppc_xive_src_block *sb)
{
	int i;

	for (i = 0; i < KVMPPC_XICS_IRQ_PER_ICS; i++) {
		struct kvmppc_xive_irq_state *state = &sb->irq_state[i];

		if (!state->valid)
			continue;

		if (state->act_priority == MASKED)
			continue;

		arch_spin_lock(&sb->lock);
		state->eisn = 0;
		state->act_server = 0;
		state->act_priority = MASKED;
		xive_vm_esb_load(&state->ipi_data, XIVE_ESB_SET_PQ_01);
		xive_native_configure_irq(state->ipi_number, 0, MASKED, 0);
		if (state->pt_number) {
			xive_vm_esb_load(state->pt_data, XIVE_ESB_SET_PQ_01);
			xive_native_configure_irq(state->pt_number,
						  0, MASKED, 0);
		}
		arch_spin_unlock(&sb->lock);
	}
}

static int kvmppc_h_int_reset(struct kvmppc_xive *xive, unsigned long flags)
{
	struct kvm *kvm = xive->kvm;
	struct kvm_vcpu *vcpu;
	unsigned int i;

	pr_devel("H_INT_RESET flags=%08lx\n", flags);

	if (flags)
		return H_PARAMETER;

	mutex_lock(&kvm->lock);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
		unsigned int i;

		if (!xc)
			continue;

		/* TODO: Ensure no interrupt is still routed to that VP ? */

		kvmppc_xive_disable_vcpu_interrupts(vcpu);

		for (i = 0; i < KVMPPC_XIVE_Q_COUNT; i++) {

			if (xc->esc_virq[i]) {
				free_irq(xc->esc_virq[i], vcpu);
				irq_dispose_mapping(xc->esc_virq[i]);
				kfree(xc->esc_virq_names[i]);
				xc->esc_virq[i] = 0;
			}

			xive_native_cleanup_queue(vcpu, i);
		}
	}

	for (i = 0; i <= xive->max_sbid; i++) {
		if (xive->src_blocks[i])
			kvmppc_xive_reset_sources(xive->src_blocks[i]);
	}

	mutex_unlock(&kvm->lock);

	return H_SUCCESS;
}

int kvmppc_xive_hcall(struct kvm_vcpu *vcpu, u32 req)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	int rc;

	if (!xive || !vcpu->arch.xive_vcpu)
		return H_FUNCTION;

	switch (req) {
	case H_INT_SET_QUEUE_CONFIG:
		rc = kvmppc_h_int_set_queue_config(vcpu,
						   kvmppc_get_gpr(vcpu, 4),
						   kvmppc_get_gpr(vcpu, 5),
						   kvmppc_get_gpr(vcpu, 6),
						   kvmppc_get_gpr(vcpu, 7),
						   kvmppc_get_gpr(vcpu, 8));
		break;

	case H_INT_SET_SOURCE_CONFIG:
		rc = kvmppc_h_int_set_source_config(vcpu,
						    kvmppc_get_gpr(vcpu, 4),
						    kvmppc_get_gpr(vcpu, 5),
						    kvmppc_get_gpr(vcpu, 6),
						    kvmppc_get_gpr(vcpu, 7),
						    kvmppc_get_gpr(vcpu, 8));
		break;

	case H_INT_RESET:
		rc = kvmppc_h_int_reset(xive, kvmppc_get_gpr(vcpu, 4));
		break;

	default:
		rc =  H_NOT_AVAILABLE;
	}

	return rc;
}
EXPORT_SYMBOL_GPL(kvmppc_xive_hcall);

static int xive_native_debug_show(struct seq_file *m, void *private)
{
	struct kvmppc_xive *xive = m->private;
	struct kvm *kvm = xive->kvm;
	struct kvm_vcpu *vcpu;
	unsigned int i;

	if (!kvm)
		return 0;

	seq_puts(m, "=========\nVCPU state\n=========\n");

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;

		if (!xc)
			continue;

		seq_printf(m, "cpu server %#x NSR=%02x CPPR=%02x IBP=%02x PIPR=%02x w01=%016llx w2=%08x\n",
			   xc->server_num,
			   vcpu->arch.xive_saved_state.nsr,
			   vcpu->arch.xive_saved_state.cppr,
			   vcpu->arch.xive_saved_state.ipb,
			   vcpu->arch.xive_saved_state.pipr,
			   vcpu->arch.xive_saved_state.w01,
			   (u32) vcpu->arch.xive_cam_word);

		kvmppc_xive_debug_show_queues(m, vcpu);

		/* TODO: hcalls statistics */
	}

	return 0;
}

static int xive_native_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, xive_native_debug_show, inode->i_private);
}

static const struct file_operations xive_native_debug_fops = {
	.open = xive_native_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void xive_native_debugfs_init(struct kvmppc_xive *xive)
{
	char *name;

	name = kasprintf(GFP_KERNEL, "kvm-xive-%p", xive);
	if (!name) {
		pr_err("%s: no memory for name\n", __func__);
		return;
	}

	xive->dentry = debugfs_create_file(name, 0444, powerpc_debugfs_root,
					   xive, &xive_native_debug_fops);

	pr_debug("%s: created %s\n", __func__, name);
	kfree(name);
}

static void kvmppc_xive_native_init(struct kvm_device *dev)
{
	struct kvmppc_xive *xive = (struct kvmppc_xive *)dev->private;

	/* Register some debug interfaces */
	xive_native_debugfs_init(xive);
}

struct kvm_device_ops kvm_xive_native_ops = {
	.name = "kvm-xive-native",
	.create = kvmppc_xive_native_create,
	.init = kvmppc_xive_native_init,
	.destroy = kvmppc_xive_native_free,
	.set_attr = kvmppc_xive_native_set_attr,
	.get_attr = kvmppc_xive_native_get_attr,
	.has_attr = kvmppc_xive_native_has_attr,
};

void kvmppc_xive_native_init_module(void)
{
	__xive_vm_h_int_get_source_info = xive_vm_h_int_get_source_info;
	__xive_vm_h_int_get_source_config = xive_vm_h_int_get_source_config;
	__xive_vm_h_int_get_queue_info = xive_vm_h_int_get_queue_info;
	__xive_vm_h_int_get_queue_config = xive_vm_h_int_get_queue_config;
	__xive_vm_h_int_set_os_reporting_line =
		xive_vm_h_int_set_os_reporting_line;
	__xive_vm_h_int_get_os_reporting_line =
		xive_vm_h_int_get_os_reporting_line;
	__xive_vm_h_int_esb = xive_vm_h_int_esb;
	__xive_vm_h_int_sync = xive_vm_h_int_sync;
}

void kvmppc_xive_native_exit_module(void)
{
	__xive_vm_h_int_get_source_info = NULL;
	__xive_vm_h_int_get_source_config = NULL;
	__xive_vm_h_int_get_queue_info = NULL;
	__xive_vm_h_int_get_queue_config = NULL;
	__xive_vm_h_int_set_os_reporting_line = NULL;
	__xive_vm_h_int_get_os_reporting_line = NULL;
	__xive_vm_h_int_esb = NULL;
	__xive_vm_h_int_sync = NULL;
}
