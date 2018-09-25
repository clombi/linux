/*
 * Copyright (c) 2017-2018, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

/* File to be included by other .c files */

#define XGLUE(a, b) a##b
#define GLUE(a, b) XGLUE(a, b)

X_STATIC int GLUE(X_PFX, h_int_get_source_info)(struct kvm_vcpu *vcpu,
						unsigned long flags,
						unsigned long irq)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	struct xive_irq_data *xd;
	u32 hw_num;
	u16 src;
	unsigned long esb_addr;

	pr_devel("H_INT_GET_SOURCE_INFO flags=%08lx irq=%lx\n", flags, irq);

	if (!xive)
		return H_FUNCTION;

	if (flags)
		return H_PARAMETER;

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb) {
		pr_debug("source %lx not found !\n", irq);
		return H_P2;
	}
	state = &sb->irq_state[src];

	arch_spin_lock(&sb->lock);
	kvmppc_xive_select_irq(state, &hw_num, &xd);

	vcpu->arch.regs.gpr[4] = 0;
	if (xd->flags & XIVE_IRQ_FLAG_STORE_EOI)
		vcpu->arch.regs.gpr[4] |= XIVE_SPAPR_SRC_STORE_EOI;

	if (state->lsi)
		vcpu->arch.regs.gpr[4] |= XIVE_SPAPR_SRC_LSI;

	/* Linux/KVM uses a two pages ESB setting, one for trigger and
	 * one for EOI */
	esb_addr = xive->vc_base + (irq << (PAGE_SHIFT + 1));

	/* Trigger page is always the first/even page */
	if (xd->trig_page)
		vcpu->arch.regs.gpr[6] = esb_addr;
	else
		vcpu->arch.regs.gpr[6] = -1;

	/* EOI/management page is the second/odd page */
	if (xd->eoi_page)
		vcpu->arch.regs.gpr[5] = esb_addr + (1ull << PAGE_SHIFT);
	else
		vcpu->arch.regs.gpr[5] = -1;

	vcpu->arch.regs.gpr[7] = PAGE_SHIFT;
	arch_spin_unlock(&sb->lock);
	return H_SUCCESS;
}

X_STATIC int GLUE(X_PFX, h_int_get_source_config)(struct kvm_vcpu *vcpu,
						  unsigned long flags,
						  unsigned long irq)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	u16 src;

	pr_devel("H_INT_GET_SOURCE_CONFIG flags=%08lx irq=%lx\n", flags, irq);

	if (!xive)
		return H_FUNCTION;

	if (flags)
		return H_PARAMETER;

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb) {
		pr_debug("source %lx not found !\n", irq);
		return H_P2;
	}
	state = &sb->irq_state[src];

	arch_spin_lock(&sb->lock);
	vcpu->arch.regs.gpr[4] = state->act_server;
	vcpu->arch.regs.gpr[5] = state->act_priority;
	vcpu->arch.regs.gpr[6] = state->number;
	arch_spin_unlock(&sb->lock);

	return H_SUCCESS;
}

X_STATIC int GLUE(X_PFX, h_int_get_queue_info)(struct kvm_vcpu *vcpu,
					       unsigned long flags,
					       unsigned long server,
					       unsigned long priority)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	struct xive_q *q;

	pr_devel("H_INT_GET_QUEUE_INFO flags=%08lx server=%ld priority=%ld\n",
		 flags, server, priority);

	if (!xive)
		return H_FUNCTION;

	if (flags)
		return H_PARAMETER;

	if (xc->server_num != server) {
		struct kvm_vcpu *vc;

		vc = kvmppc_xive_find_server(vcpu->kvm, server);
		if (!vc) {
			pr_debug("server %ld not found\n", server);
			return H_P2;
		}
		xc = vc->arch.xive_vcpu;
	}

	if (priority != xive_prio_from_guest(priority) || priority == MASKED) {
		pr_debug("invalid priority for queue %ld for VCPU %ld\n",
		       priority, server);
		return H_P3;
	}
	q = &xc->queues[priority];

	vcpu->arch.regs.gpr[4] = q->eoi_phys;
	/* TODO: Power of 2 page size of the notification page */
	vcpu->arch.regs.gpr[5] = 0;
	return H_SUCCESS;
}

X_STATIC int GLUE(X_PFX, get_queue_state)(struct kvm_vcpu *vcpu,
					  struct kvmppc_xive_vcpu *xc,
					  unsigned long prio)
{
	int rc;
	u32 version;
	u64 qw1;
	bool qtoggle;
	u32 page_off;

	rc = xive_native_get_queue_state(xc->vp_id, prio, &version, &qw1);
	if (rc)
		return rc;

	if (XIVE_STATE_COMPAT(version) > 1) {
		pr_err("invalid OPAL state version %08x\n", version);
		return -EIO;
	}

	qtoggle = GETFIELD(EQ_W1_GENERATION, qw1);
	page_off = GETFIELD(EQ_W1_PAGE_OFF, qw1);

	vcpu->arch.regs.gpr[4] |= ((unsigned long) qtoggle) << 62;
	vcpu->arch.regs.gpr[7] = page_off;
	return 0;
}

X_STATIC int GLUE(X_PFX, h_int_get_queue_config)(struct kvm_vcpu *vcpu,
						 unsigned long flags,
						 unsigned long server,
						 unsigned long priority)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;
	struct xive_q *q;
	u64 qpage;
	u64 qsize;
	u64 qeoi_page;
	u32 escalate_irq;
	u64 qflags;
	int rc;

	pr_devel("H_INT_GET_QUEUE_CONFIG flags=%08lx server=%ld priority=%ld\n",
		 flags, server, priority);

	if (!xive)
		return H_FUNCTION;

	if (flags & ~XIVE_SPAPR_EQ_DEBUG)
		return H_PARAMETER;

	if (xc->server_num != server) {
		struct kvm_vcpu *vc;

		vc = kvmppc_xive_find_server(vcpu->kvm, server);
		if (!vc) {
			pr_debug("server %ld not found\n", server);
			return H_P2;
		}
		xc = vc->arch.xive_vcpu;
	}

	if (priority != xive_prio_from_guest(priority) || priority == MASKED) {
		pr_debug("invalid priority for queue %ld for VCPU %ld\n",
		       priority, server);
		return H_P3;
	}
	q = &xc->queues[priority];

	rc = xive_native_get_queue_info(xc->vp_id, priority, &qpage, &qsize,
					&qeoi_page, &escalate_irq, &qflags);
	if (rc)
		return H_HARDWARE;

	vcpu->arch.regs.gpr[4] = qflags;
	vcpu->arch.regs.gpr[5] = qpage;
	vcpu->arch.regs.gpr[6] = qsize;
	if (flags & XIVE_SPAPR_EQ_DEBUG) {
		rc = GLUE(X_PFX, get_queue_state)(vcpu, xc, priority);
		if (rc)
			return H_HARDWARE;
	}
	return H_SUCCESS;
}

/* TODO H_INT_SET_OS_REPORTING_LINE */
X_STATIC int GLUE(X_PFX, h_int_set_os_reporting_line)(struct kvm_vcpu *vcpu,
						      unsigned long flags,
						      unsigned long line)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;

	pr_devel("H_INT_SET_OS_REPORTING_LINE flags=%08lx line=%ld\n",
		 flags, line);

	if (!xive)
		return H_FUNCTION;

	if (flags)
		return H_PARAMETER;

	return H_FUNCTION;
}

/* TODO H_INT_GET_OS_REPORTING_LINE*/
X_STATIC int GLUE(X_PFX, h_int_get_os_reporting_line)(struct kvm_vcpu *vcpu,
						      unsigned long flags,
						      unsigned long server,
						      unsigned long line)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_vcpu *xc = vcpu->arch.xive_vcpu;

	pr_devel("H_INT_GET_OS_REPORTING_LINE flags=%08lx server=%ld line=%ld\n",
		 flags, server, line);

	if (!xive)
		return H_FUNCTION;

	if (flags)
		return H_PARAMETER;

	if (xc->server_num != server) {
		struct kvm_vcpu *vc;

		vc = kvmppc_xive_find_server(vcpu->kvm, server);
		if (!vc) {
			pr_debug("server %ld not found\n", server);
			return H_P2;
		}
		xc = vc->arch.xive_vcpu;
	}

	return H_FUNCTION;

}

/*
 * TODO: introduce a common template file with the XIVE native layer
 * and the XICS-on-XIVE glue for the utility functions
 */
static u8 GLUE(X_PFX, esb_load)(struct xive_irq_data *xd, u32 offset)
{
	u64 val;

	if (xd->flags & XIVE_IRQ_FLAG_SHIFT_BUG)
		offset |= offset << 4;

	val = __x_readq(__x_eoi_page(xd) + offset);
#ifdef __LITTLE_ENDIAN__
	val >>= 64-8;
#endif
	return (u8)val;
}

static u8 GLUE(X_PFX, esb_store)(struct xive_irq_data *xd, u32 offset, u64 data)
{
	u64 val;

	if (xd->flags & XIVE_IRQ_FLAG_SHIFT_BUG)
		offset |= offset << 4;

	val = __x_readq(__x_eoi_page(xd) + offset);
#ifdef __LITTLE_ENDIAN__
	val >>= 64-8;
#endif
	return (u8)val;
}

X_STATIC int GLUE(X_PFX, h_int_esb)(struct kvm_vcpu *vcpu, unsigned long flags,
				    unsigned long irq, unsigned long offset,
				    unsigned long data)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	struct xive_irq_data *xd;
	u32 hw_num;
	u16 src;

	pr_devel("H_INT_ESB flags=%08lx irq=%lx offset=%lx data=%lx\n",
		 flags, irq, offset, data);

	if (!xive)
		return H_FUNCTION;

	if (flags)
		return H_PARAMETER;

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb) {
		pr_debug("source %lx not found !\n", irq);
		return H_P2;
	}
	state = &sb->irq_state[src];

	if (offset > (1ull << PAGE_SHIFT))
		return H_P3;

	arch_spin_lock(&sb->lock);
	kvmppc_xive_select_irq(state, &hw_num, &xd);

	if (flags & XIVE_SPAPR_ESB_STORE) {
		GLUE(X_PFX, esb_store)(xd, offset, data);
		vcpu->arch.regs.gpr[4] = -1;
	} else {
		vcpu->arch.regs.gpr[4] = GLUE(X_PFX, esb_load)(xd, offset);
	}
	arch_spin_unlock(&sb->lock);

	return H_SUCCESS;
}

X_STATIC int GLUE(X_PFX, h_int_sync)(struct kvm_vcpu *vcpu, unsigned long flags,
				     unsigned long irq)
{
	struct kvmppc_xive *xive = vcpu->kvm->arch.xive;
	struct kvmppc_xive_src_block *sb;
	struct kvmppc_xive_irq_state *state;
	struct xive_irq_data *xd;
	u32 hw_num;
	u16 src;

	pr_devel("H_INT_SYNC flags=%08lx irq=%lx\n", flags, irq);

	if (!xive)
		return H_FUNCTION;

	if (flags)
		return H_PARAMETER;

	sb = kvmppc_xive_find_source(xive, irq, &src);
	if (!sb) {
		pr_debug("source %lx not found !\n", irq);
		return H_P2;
	}
	state = &sb->irq_state[src];

	arch_spin_lock(&sb->lock);

	kvmppc_xive_select_irq(state, &hw_num, &xd);
	xive_native_sync_source(hw_num);

	arch_spin_unlock(&sb->lock);
	return H_SUCCESS;
}
