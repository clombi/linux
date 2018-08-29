// SPDX-License-Identifier: GPL-2.0+
// Copyright 2018 IBM Corp.
#include <misc/ocxl-config.h>
#include "ocxl_internal.h"

#define TL_MAX_TEMPLATE        63
#define TL_BITS_PER_RATE       4
#define TL_RATE_BUF_SIZE       ((TL_MAX_TEMPLATE+1) * TL_BITS_PER_RATE / 8)

#define TL_P9_RECV_CAP         0x000000000000000Full

#define AFU_PRESENT            (1 << 31)
#define AFU_INDEX_MASK         0x3F000000
#define AFU_INDEX_SHIFT        24
#define ACTAG_MASK             0xFFF

#define TEMPL_LEN              0x58

#define STORE_LE32(addr, val)   (*(u32 *)addr = val)

#define PASID_BITS             15
#define PASID_MAX              ((1 << PASID_BITS) - 1)

u8 *afud_temp0;

static void set_templ_rate(unsigned int templ, unsigned int rate, char *buf)
{
	int shift, idx;

	WARN_ON(templ > TL_MAX_TEMPLATE);
	idx = (TL_MAX_TEMPLATE - templ) / 2;
	shift = 4 * (1 - ((TL_MAX_TEMPLATE - templ) % 2));
	buf[idx] |= rate << shift;
}

static int ocxl_guest_alloc_xive_irq(u32 *irq, u64 *trigger_addr)
{
	u32 hwirq;

	hwirq = 0;  /* TO DO */ 

	*irq = hwirq;
	*trigger_addr = 0x0600000000000000uLL; /* TO DO */
	return 0;

}

static void ocxl_guest_free_xive_irq(u32 irq)
{
	/* TO DO */
	return;
}

static int ocxl_guest_get_actag(struct pci_dev *dev, u16 *base, u16 *enabled,
			       u16 *supported)
{
	int pos, afu_idx = -1, i;
	u16 actag = 0, actag_sup, actag_sup_max = 0;
	u32 val;

	/* May be the actag count for each afu has to be present in
	 * device-tree instead of config space ?
	 */

	/* get max afu index */
	pos = ocxl_find_dvsec(dev, OCXL_DVSEC_FUNC_ID);
	if (!pos)
		return -ESRCH;

	pci_read_config_dword(dev, pos + OCXL_DVSEC_FUNC_OFF_INDEX, &val);
	if (val & AFU_PRESENT)
		afu_idx = (val & AFU_INDEX_MASK) >> AFU_INDEX_SHIFT;
	else
		afu_idx = -1;

	/* calculate total actag */
	for (i = 0; i <= afu_idx; i++) {
		pos = ocxl_find_dvsec_afu_ctrl(dev, 0);
		if (!pos)
			return -ESRCH;

		pci_read_config_word(dev, pos + OCXL_DVSEC_AFU_CTRL_ACTAG_SUP,
				     &actag_sup);
		actag_sup = actag_sup & ACTAG_MASK;
		actag_sup_max = (actag_sup_max < actag_sup)? actag_sup: actag_sup_max;
		actag += actag_sup;
	}

	*base      = 0;
	*enabled   = actag;
	*supported = actag_sup;
	return 0;
}

static int ocxl_guest_get_pasid_count(struct pci_dev *dev, int *count)
{
*count = PASID_MAX;
	return 0;
}

static int ocxl_guest_get_tl_cap(struct pci_dev *dev, long *cap,
			char *rate_buf, int rate_buf_size)
{
	if (rate_buf_size != TL_RATE_BUF_SIZE)
		return -EINVAL;
	/*
	 * The TL capabilities are a characteristic of the NPU, so
	 * we go with hard-coded values.
	 *
	 * The receiving rate of each template is encoded on 4 bits.
	 *
	 * On P9:
	 * - templates 0 -> 3 are supported
	 * - templates 0, 1 and 3 have a 0 receiving rate
	 * - template 2 has receiving rate of 1 (extra cycle)
	 */
	memset(rate_buf, 0, rate_buf_size);
	set_templ_rate(2, 1, rate_buf);
	*cap = TL_P9_RECV_CAP;
	return 0;
}

static int ocxl_guest_get_xsl_irq(struct pci_dev *dev, int *hwirq)
{
	int rc;

	rc = of_property_read_u32(dev->dev.of_node, "ibm,xsl-irq", hwirq);
	if (rc) {
		dev_err(&dev->dev,
			"Can't get translation interrupt for device\n");
		return rc;
	}
	return 0;
}

static int ocxl_guest_map_xsl_regs(struct pci_dev *dev, void __iomem **dsisr,
			void __iomem **dar, void __iomem **tfc,
			void __iomem **pe_handle)
{
	u64 reg;
	int i, j, rc = 0;
	void __iomem *regs[4];

	/*
	 * get the mmio addresses of the DSISR, DAR, TFC and
	 * PE_HANDLE registers in a device tree property, in that
	 * order
	 */
	for (i = 0; i < 4; i++) {
		rc = of_property_read_u64_index(dev->dev.of_node,
						"ibm,xsl-mmio", i, &reg);
		if (rc)
			break;
		regs[i] = ioremap(reg, 8);
		if (!regs[i]) {
			rc = -EINVAL;
			break;
		}
	}
	if (rc) {
		dev_err(&dev->dev, "Can't map translation mmio registers\n");
		for (j = i - 1; j >= 0; j--)
			iounmap(regs[j]);
	} else {
		*dsisr = regs[0];
		*dar = regs[1];
		*tfc = regs[2];
		*pe_handle = regs[3];
	}
	return rc;
}

static int ocxl_guest_read_afu_info(struct pci_dev *dev, struct ocxl_fn_config *fn,
			int offset, u32 *data)
{
	if (!afud_temp0) {
		afud_temp0 = kzalloc(TEMPL_LEN, GFP_KERNEL);
		STORE_LE32((u32 *)&afud_temp0[0x0], 0x00580005);
		STORE_LE32((u32 *)&afud_temp0[0x4], 0x49424d2c);
		STORE_LE32((u32 *)&afud_temp0[0x8], 0x4d454d43);
		STORE_LE32((u32 *)&afud_temp0[0xC], 0x50593300);
		STORE_LE32((u32 *)&afud_temp0[0x10], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x14], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x18], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x1C], 0x01002401);
		STORE_LE32((u32 *)&afud_temp0[0x20], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x24], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x28], 0x02000000);
		STORE_LE32((u32 *)&afud_temp0[0x2C], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x30], 0x02000000);
		STORE_LE32((u32 *)&afud_temp0[0x34], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x38], 0x00010000);
		STORE_LE32((u32 *)&afud_temp0[0x3C], 0x0000001a);
		STORE_LE32((u32 *)&afud_temp0[0x40], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x44], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x48], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x4C], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x50], 0x00000000);
		STORE_LE32((u32 *)&afud_temp0[0x54], 0x00000000);
	}

	*data = be32_to_cpu((*(u32 *)(afud_temp0 + offset)));
	return 0;
}

static int ocxl_guest_set_tl_conf(struct pci_dev *dev, long cap,
			uint64_t rate_buf_phys, int rate_buf_size)
{
	return 0;
}

static void ocxl_guest_spa_release(void *platform_data)
{
	return;
}

static int ocxl_guest_spa_remove_pe_from_cache(void *platform_data, int pe_handle)
{
	return 0;
}

static int ocxl_guest_spa_setup(struct pci_dev *dev, void *spa_mem, int PE_mask,
				void **platform_data)
{
	*platform_data = NULL;
	return 0;
}

static void ocxl_guest_unmap_xsl_regs(void __iomem *dsisr, void __iomem *dar,
			void __iomem *tfc, void __iomem *pe_handle)
{
	iounmap(dsisr);
	iounmap(dar);
	iounmap(tfc);
	iounmap(pe_handle);
}

const struct ocxl_backend_ops ocxl_guest_ops = {
	.module = THIS_MODULE,
	.alloc_xive_irq = ocxl_guest_alloc_xive_irq,
	.free_xive_irq = ocxl_guest_free_xive_irq,
	.get_actag = ocxl_guest_get_actag,
	.get_pasid_count = ocxl_guest_get_pasid_count,
	.get_tl_cap = ocxl_guest_get_tl_cap,
	.get_xsl_irq = ocxl_guest_get_xsl_irq,
	.map_xsl_regs = ocxl_guest_map_xsl_regs,
	.read_afu_info = ocxl_guest_read_afu_info,
	.set_tl_conf = ocxl_guest_set_tl_conf,
	.spa_release = ocxl_guest_spa_release,
	.spa_remove_pe_from_cache = ocxl_guest_spa_remove_pe_from_cache,
	.spa_setup = ocxl_guest_spa_setup,
	.unmap_xsl_regs = ocxl_guest_unmap_xsl_regs,
};
