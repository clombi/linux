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
	/* There are two ESB pages (trigger and EOI) per IRQ */
	if (vma_pages(vma) + vma->vm_pgoff > KVMPPC_XIVE_NR_IRQS * 2)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_ops = &xive_native_esb_vmops;
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

static int kvmppc_xive_native_set_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	struct kvmppc_xive *xive = dev->private;

	switch (attr->group) {
	case KVM_DEV_XIVE_GRP_SOURCES:
		return kvmppc_xive_native_set_source(xive, attr->attr,
						     attr->addr);
	}
	return -ENXIO;
}

static int kvmppc_xive_native_get_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	struct kvmppc_xive *xive = dev->private;

	switch (attr->group) {
	case KVM_DEV_XIVE_GRP_CTRL:
		switch (attr->attr) {
		case KVM_DEV_XIVE_GET_ESB_FD:
			return kvmppc_xive_native_get_esb_fd(xive, attr->addr);
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
		if (attr->attr >= KVMPPC_XIVE_FIRST_IRQ &&
		    attr->attr < KVMPPC_XIVE_NR_IRQS)
			return 0;
		break;
	case KVM_DEV_XIVE_GRP_CTRL:
		switch (attr->attr) {
		case KVM_DEV_XIVE_GET_ESB_FD:
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

	xive->single_escalation = xive_native_has_single_escalation();

	if (ret)
		kfree(xive);

	return ret;
}

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
	;
}

void kvmppc_xive_native_exit_module(void)
{
	;
}
