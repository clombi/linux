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

#define HCALL_TIMEOUT          60000
#define H_SPA_SETUP            0xf003

/* temporarly solution */
u32 afu_hwirq;

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
	*irq = afu_hwirq;
	*trigger_addr = 0x0600000000000000uLL; /* TO DO */
	return 0;

}

static void ocxl_guest_free_xive_irq(u32 irq)
{
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

	rc = of_property_read_u32(dev->dev.of_node, "ibm,afu-irq", &afu_hwirq);
	if (rc) {
		dev_err(&dev->dev,
			"Can't get afu interrupt for device\n");
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

static void ocxl_guest_set_pe(struct ocxl_process_element *pe, u32 pidr,
                              u32 tidr, u64 amr)
{
	pe->config_state = 0;	/* TO DO */
	pe->lpid = 0;		/* TO DO */
	pe->pid = cpu_to_be32(pidr);
	pe->tid = cpu_to_be32(tidr);
	pe->amr = cpu_to_be64(amr);
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
	unsigned int delay, total_delay = 0;
	long rc;

	while (1) {
		rc = plpar_hcall_norets(H_SPA_SETUP, virt_to_phys(spa_mem));

		if (rc != H_BUSY && !H_IS_LONG_BUSY(rc))
			break;

		if (rc == H_BUSY)
			delay = 10;
		else
			delay = get_longbusy_msecs(rc);

		total_delay += delay;
		if (total_delay > HCALL_TIMEOUT) {
			WARN(1, "Warning: Giving up waiting for hcall H_SPA_SETUP after %u msec\n", total_delay);
			rc = H_BUSY;
			break;
		}
		mdelay(delay);
	};

	if (rc)
		pr_err("H_SPA_SETUP failed %ld\n", rc);

	*platform_data = NULL;
	return rc;
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
	.set_pe = ocxl_guest_set_pe,
	.set_tl_conf = ocxl_guest_set_tl_conf,
	.spa_release = ocxl_guest_spa_release,
	.spa_remove_pe_from_cache = ocxl_guest_spa_remove_pe_from_cache,
	.spa_setup = ocxl_guest_spa_setup,
	.unmap_xsl_regs = ocxl_guest_unmap_xsl_regs,
};
