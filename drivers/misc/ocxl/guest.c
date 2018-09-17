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

#define PASID_BITS             15
#define PASID_MAX              ((1 << PASID_BITS) - 1)

#define H_IRQ_INFO             0xf003
#define H_ATTACH_PE            0xf004
#define H_READ_XSL_REGS        0xf005

struct device_data {
	u64 buid;
	u32 config_addr;
};

/* temporarly solution */
int xsl_hwirq;
int afu_hwirq[5];
int irq_index = 0;

static void set_templ_rate(unsigned int templ, unsigned int rate, char *buf)
{
	int shift, idx;

	WARN_ON(templ > TL_MAX_TEMPLATE);
	idx = (TL_MAX_TEMPLATE - templ) / 2;
	shift = 4 * (1 - ((TL_MAX_TEMPLATE - templ) % 2));
	buf[idx] |= rate << shift;
}

static int ocxl_guest_alloc_xive_irq(void *platform_data, u32 *irq,
				     u64 *trigger_addr)
{
	struct device_data {
		u64 buid;
		u32 config_addr;
	} *data = platform_data;
	long rc;

	rc = plpar_hcall_norets(H_IRQ_INFO, data->buid,
				data->config_addr, xsl_hwirq, afu_hwirq[irq_index]);
	if (rc)
		pr_err("H_IRQ_INFO failed (%ld)\n", rc);

	*irq = afu_hwirq[irq_index++];
	if (irq_index == 5)
		irq_index = 0;
	*trigger_addr = 0x0600000000000000uLL; /* TO DO */
	return rc;
}

static void ocxl_guest_free_xive_irq(u32 irq)
{
	return;
}

static int ocxl_guest_get_actag(struct pci_dev *dev, u16 *base,
				u16 *enabled, u16 *supported)
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

static int ocxl_guest_get_tl_rate_buf_size(void) {
	return TL_RATE_BUF_SIZE;
}

static int ocxl_guest_get_xsl_irq(struct pci_dev *dev, int *hwirq)
{
	int rc, i;
	char name[20];

	rc = of_property_read_u32(dev->dev.of_node, "ibm,xsl-irq", hwirq);
	if (rc) {
		dev_err(&dev->dev,
			"Can't get translation interrupt for device\n");
		return rc;
	}
	xsl_hwirq = *hwirq;

	for (i = 0; i < 5; i++) {
		sprintf(name, "ibm,afu-irq-%i", i);
		rc = of_property_read_u32(dev->dev.of_node, name,
					  &afu_hwirq[i]);
		if (rc) {
			dev_err(&dev->dev,
				"Can't get afu interrupt for device\n");
			return rc;
		}
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

static void ocxl_guest_read_irq(void __iomem *reg_dsisr,
				void __iomem *reg_dar,
				void __iomem *reg_pe,
				void *platform_data,
				u64 *dsisr, u64 *dar, u64 *pe)
{
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	long rc;
	struct guest_platform_data {
		u64 buid;
		u32 config_addr;
	} *data = platform_data;

	rc = plpar_hcall(H_READ_XSL_REGS, retbuf, data->buid,
			 data->config_addr);
	if (rc)
		pr_err("H_READ_XSL_REGS failed (%ld)\n", rc);
	
	*dsisr = retbuf[0];
	*dar = retbuf[1];
	*pe = retbuf[2];
}

static void ocxl_guest_release_platform(void *platform_data)
{
	struct device_data *data;

	data = (struct device_data *)platform_data;
	if (data)
		kfree(data);
}

static int ocxl_guest_remove_pe_from_cache(void *platform_data,
					   int pe_handle)
{
	return 0;
}

static void ocxl_guest_set_pe(void *platform_data, int pasid,
			      struct ocxl_process_element *pe, u32 pidr,
                              u32 tidr, u64 amr)
{
	struct device_data {
		u64 buid;
		u32 config_addr;
	} *data = platform_data;
	long rc;

	rc = plpar_hcall_norets(H_ATTACH_PE, data->buid,
				data->config_addr, pasid, pidr);
	if (rc)
		pr_err("H_ATTACH_PE failed (%ld)\n", rc);

	pe->config_state = 0;	/* TO DO */
	pe->lpid = 0;		/* TO DO */
	pe->pid = cpu_to_be32(pidr);
	pe->tid = cpu_to_be32(tidr);
	pe->amr = cpu_to_be64(amr);
}

static int ocxl_guest_set_tl_conf(struct pci_dev *dev, long cap,
				  uint64_t rate_buf_phys,
				  int rate_buf_size)
{
	return 0;
}

static int ocxl_guest_setup_platform(struct pci_dev *dev, void *mem,
				     int PE_mask, void **platform_data)
{
	struct device_node *dn;
	struct pci_dn *pdn;
	int bus, devfn;
	struct device_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	dn = pci_device_to_OF_node(dev);
	pdn = PCI_DN(dn);
	data->buid = pdn->phb->buid;

	bus = dev->bus->number;
	devfn = dev->devfn;
	data->config_addr = ((bus & 0xFF) << 16) + ((devfn & 0xFF) << 8);

	pr_debug("%s - buid: %#llx, bus: %d, devfn: %d, config_addr: %#x\n",
		 __func__, data->buid, bus, devfn, data->config_addr);

	*platform_data = data;
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
	.get_tl_rate_buf_size = ocxl_guest_get_tl_rate_buf_size,
	.get_xsl_irq = ocxl_guest_get_xsl_irq,
	.map_xsl_regs = ocxl_guest_map_xsl_regs,
	.read_irq = ocxl_guest_read_irq,
	.release_platform = ocxl_guest_release_platform,
	.remove_pe_from_cache = ocxl_guest_remove_pe_from_cache,
	.set_pe = ocxl_guest_set_pe,
	.set_tl_conf = ocxl_guest_set_tl_conf,
	.setup_platform = ocxl_guest_setup_platform,
	.unmap_xsl_regs = ocxl_guest_unmap_xsl_regs,
};
