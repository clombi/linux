// SPDX-License-Identifier: GPL-2.0+
// Copyright 2018 IBM Corp.
#include <asm/pnv-ocxl.h>
#include <misc/ocxl-config.h>
#include "ocxl_internal.h"

#define SPA_CFG_SF              (1ull << (63-0))
#define SPA_CFG_TA              (1ull << (63-1))
#define SPA_CFG_HV              (1ull << (63-3))
#define SPA_CFG_UV              (1ull << (63-4))
#define SPA_CFG_XLAT_hpt        (0ull << (63-6)) /* Hashed page table (HPT) mode */
#define SPA_CFG_XLAT_roh        (2ull << (63-6)) /* Radix on HPT mode */
#define SPA_CFG_XLAT_ror        (3ull << (63-6)) /* Radix on Radix mode */
#define SPA_CFG_PR              (1ull << (63-49))
#define SPA_CFG_TC              (1ull << (63-54))
#define SPA_CFG_DR              (1ull << (63-59))


static u64 calculate_cfg_state(bool kernel)
{
	u64 state;

	state = SPA_CFG_DR;
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		state |= SPA_CFG_TC;
	if (radix_enabled())
		state |= SPA_CFG_XLAT_ror;
	else
		state |= SPA_CFG_XLAT_hpt;
	state |= SPA_CFG_HV;
	if (kernel) {
		if (mfmsr() & MSR_SF)
			state |= SPA_CFG_SF;
	} else {
		state |= SPA_CFG_PR;
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			state |= SPA_CFG_SF;
	}
	return state;
}

static int ocxl_native_alloc_xive_irq(void *platform_data, u32 *irq,
				      u64 *trigger_addr)
{
	return pnv_ocxl_alloc_xive_irq(irq, trigger_addr);
}

static void ocxl_native_free_xive_irq(u32 irq)
{
	pnv_ocxl_free_xive_irq(irq);
}

static int ocxl_native_get_actag(struct pci_dev *dev, u16 *base,
				 u16 *enabled, u16 *supported)
{
	return pnv_ocxl_get_actag(dev, base, enabled, supported);
}

static int ocxl_native_get_pasid_count(struct pci_dev *dev, int *count)
{
	return pnv_ocxl_get_pasid_count(dev, count);
}

static int ocxl_native_get_tl_cap(struct pci_dev *dev, long *cap,
			char *rate_buf, int rate_buf_size)
{
	return pnv_ocxl_get_tl_cap(dev, cap, rate_buf, rate_buf_size);
}

static int ocxl_native_get_tl_rate_buf_size(void)
{
	return PNV_OCXL_TL_RATE_BUF_SIZE;
}

static int ocxl_native_get_xsl_irq(struct pci_dev *dev, int *hwirq)
{
	return pnv_ocxl_get_xsl_irq(dev, hwirq);
}

static int ocxl_native_map_xsl_regs(struct pci_dev *dev, void __iomem **dsisr,
			void __iomem **dar, void __iomem **tfc,
			void __iomem **pe_handle)
{
	return pnv_ocxl_map_xsl_regs(dev, dsisr, dar, tfc, pe_handle);
}

static void ocxl_native_read_irq(void __iomem *reg_dsisr,
				 void __iomem *reg_dar,
				 void __iomem *reg_pe,
				 void *platform_data,
				 u64 *dsisr, u64 *dar, u64 *pe)
{
	*dsisr = in_be64(reg_dsisr);
	*dar = in_be64(reg_dar);
	*pe = in_be64(reg_pe);
}

static void ocxl_native_release_platform(void *platform_data)
{
	return pnv_ocxl_spa_release(platform_data);
}

static int ocxl_native_remove_pe_from_cache(void *platform_data,
					    int pe_handle)
{
	return pnv_ocxl_spa_remove_pe_from_cache(platform_data, pe_handle);
}

static void ocxl_native_set_pe(void *platform_data, int pasid,
			       struct ocxl_process_element *pe,
			       u32 pidr, u32 tidr, u64 amr)
{
	pe->config_state = cpu_to_be64(calculate_cfg_state(pidr == 0));
	pe->lpid = cpu_to_be32(mfspr(SPRN_LPID));
	pe->pid = cpu_to_be32(pidr);
	pe->tid = cpu_to_be32(tidr);
	pe->amr = cpu_to_be64(amr);
}

static int ocxl_native_set_tl_conf(struct pci_dev *dev, long cap,
			uint64_t rate_buf_phys, int rate_buf_size)
{
	return pnv_ocxl_set_tl_conf(dev, cap, rate_buf_phys, rate_buf_size);
}

static int ocxl_native_setup_platform(struct pci_dev *dev, void *mem,
				      int PE_mask, void **platform_data)
{
	return pnv_ocxl_spa_setup(dev, mem, PE_mask, platform_data);
}

static void ocxl_native_unmap_xsl_regs(void __iomem *dsisr, void __iomem *dar,
                        void __iomem *tfc, void __iomem *pe_handle)
{
	return pnv_ocxl_unmap_xsl_regs(dsisr, dar, tfc, pe_handle);
}

const struct ocxl_backend_ops ocxl_native_ops = {
	.module = THIS_MODULE,
	.alloc_xive_irq = ocxl_native_alloc_xive_irq,
	.free_xive_irq = ocxl_native_free_xive_irq,
	.get_actag = ocxl_native_get_actag,
	.get_pasid_count = ocxl_native_get_pasid_count,
	.get_tl_cap = ocxl_native_get_tl_cap,
	.get_tl_rate_buf_size = ocxl_native_get_tl_rate_buf_size,
	.get_xsl_irq = ocxl_native_get_xsl_irq,
	.map_xsl_regs = ocxl_native_map_xsl_regs,
	.map_xsl_regs = ocxl_native_map_xsl_regs,
	.read_irq = ocxl_native_read_irq,
	.release_platform = ocxl_native_release_platform,
	.remove_pe_from_cache = ocxl_native_remove_pe_from_cache,
	.set_pe = ocxl_native_set_pe,
	.set_tl_conf = ocxl_native_set_tl_conf,
	.setup_platform = ocxl_native_setup_platform,
	.unmap_xsl_regs = ocxl_native_unmap_xsl_regs,
};
