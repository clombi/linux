// SPDX-License-Identifier: GPL-2.0+
// Copyright 2018 IBM Corp.
#include <asm/pnv-ocxl.h>
#include <misc/ocxl-config.h>
#include "ocxl_internal.h"

static int ocxl_native_alloc_xive_irq(u32 *irq, u64 *trigger_addr)
{
        return pnv_ocxl_alloc_xive_irq(irq, trigger_addr);
}

static int ocxl_native_get_actag(struct pci_dev *dev, u16 *base, u16 *enabled,
				 u16 *supported)
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

static int ocxl_native_read_afu_info(struct pci_dev *dev, struct ocxl_fn_config *fn,
				int offset, u32 *data)
{
	u32 val;
	unsigned long timeout = jiffies + (HZ * CFG_TIMEOUT);
	int pos = fn->dvsec_afu_info_pos;

	/* Protect 'data valid' bit */
	if (EXTRACT_BIT(offset, 31)) {
		dev_err(&dev->dev, "Invalid offset in AFU info DVSEC\n");
		return -EINVAL;
	}

	pci_write_config_dword(dev, pos + OCXL_DVSEC_AFU_INFO_OFF, offset);
	pci_read_config_dword(dev, pos + OCXL_DVSEC_AFU_INFO_OFF, &val);
	while (!EXTRACT_BIT(val, 31)) {
		if (time_after_eq(jiffies, timeout)) {
			dev_err(&dev->dev,
				"Timeout while reading AFU info DVSEC (offset=%d)\n",
				offset);
			return -EBUSY;
		}
		cpu_relax();
		pci_read_config_dword(dev, pos + OCXL_DVSEC_AFU_INFO_OFF, &val);
	}
	pci_read_config_dword(dev, pos + OCXL_DVSEC_AFU_INFO_DATA, data);
	return 0;
}

static int ocxl_native_set_tl_conf(struct pci_dev *dev, long cap,
			uint64_t rate_buf_phys, int rate_buf_size)
{
	return pnv_ocxl_set_tl_conf(dev, cap, rate_buf_phys, rate_buf_size);
}

static void ocxl_native_spa_release(void *platform_data)
{
	return pnv_ocxl_spa_release(platform_data);
}

static int ocxl_native_spa_setup(struct pci_dev *dev, void *spa_mem, int PE_mask,
		void **platform_data)
{
	return pnv_ocxl_spa_setup(dev, spa_mem, PE_mask, platform_data);
}

static void ocxl_native_unmap_xsl_regs(void __iomem *dsisr, void __iomem *dar,
                        void __iomem *tfc, void __iomem *pe_handle)
{
	return pnv_ocxl_unmap_xsl_regs(dsisr, dar, tfc, pe_handle);
}

const struct ocxl_backend_ops ocxl_native_ops = {
	.module = THIS_MODULE,
	.alloc_xive_irq = ocxl_native_alloc_xive_irq,
	.get_actag = ocxl_native_get_actag,
	.get_pasid_count = ocxl_native_get_pasid_count,
	.get_tl_cap = ocxl_native_get_tl_cap,
	.get_xsl_irq = ocxl_native_get_xsl_irq,
	.map_xsl_regs = ocxl_native_map_xsl_regs,
	.read_afu_info = ocxl_native_read_afu_info,
	.set_tl_conf = ocxl_native_set_tl_conf,
	.spa_release = ocxl_native_spa_release,
	.spa_setup = ocxl_native_spa_setup,
	.unmap_xsl_regs = ocxl_native_unmap_xsl_regs,
};
