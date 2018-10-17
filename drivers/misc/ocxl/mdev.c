// SPDX-License-Identifier: GPL-2.0
/*
 * Mediated device for CXL
 *
 * Copyright IBM Corp. 2018
 *
 * Author(s): Greg Kurz <groug@kaod.org>
 */

#include <linux/vfio.h>
#include <linux/mdev.h>
#include <misc/ocxl-config.h>

#include "ocxl_internal.h"

#define OCXL_DVSEC_PASID_MASK           GENMASK(19, 0)

#define OCXL_MDEV_CONFIG_SPACE_SIZE     PCI_CFG_SPACE_EXP_SIZE
#define OCXL_MDEV_EXT_CAP_CONFIG_SPACE  0x100

/* Extended Capabilities starts at offset x’100’ */
#define CAPABILITY_SIZE                 0x100

#define OCXL_PASID_MAX_WIDTH            0x4

#define PCI_EXT_CAP_VER_SHIFT           16
#define PCI_EXT_CAP_NEXT_SHIFT          20

#define PCI_EXT_CAP(id, ver, next)         \
    ((id) |                                \
     ((ver) << PCI_EXT_CAP_VER_SHIFT) |    \
     ((next) << PCI_EXT_CAP_NEXT_SHIFT))

/*BAR0 + x200_0000 : BAR0 + x3FF_FFFF
 *AFU per Process PSA (64kB per Process, max 512 processes)
 */
#define OCXL_MDEV_BAR0_REGION_OFFSET           0x1000000
#define OCXL_MDEV_BAR0_REGION_SIZE             0x4000000

/* State of each mdev device */
struct mdev_state {
	struct ocxl_fn *fn;
	struct mutex ops_lock;

	struct vfio_device_info dev_info;

	u8 *vconfig;        /* virtual PCI Config */
	u16 pasid_cap_pos;  /* Offset of PASID Capability */
	u16 dvsec_tl_pos;   /* Offset of the DVSEC - Transport Layer */
	u16 dvsec_fc_pos;   /* Offset of the DVSEC - Function Configuration */
	u16 dvsec_info_pos; /* Offset of the DVSEC - AFU information */
	u16 dvsec_control_pos; /* Offset of the DVSEC - AFU Control */

	struct ocxl_afu *afu;      /* first afu in the list */
	void __iomem *pp_mmio_ptr; /* iomap on afu pp mmio */
};

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "Virtual OpenCAPI adapter\n");
}
static MDEV_TYPE_ATTR_RO(name);

static struct attribute *mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	NULL,
};

static struct attribute_group mdev_type_group = {
	.name = "ocxl",
	.attrs = mdev_types_attrs,
};

static struct attribute_group *mdev_type_groups[] = {
	&mdev_type_group,
	NULL,
};

static void pci_read_config(struct pci_dev *pcidev,
			    void *val, size_t count, loff_t pos)
{
	switch(count) {
	case 4:
	pci_read_config_dword(pcidev, pos, (u32 *)val);
	break;
	case 2:
	pci_read_config_word(pcidev, pos, (u16 *)val);
	break;
	case 1:
	pci_read_config_byte(pcidev, pos, (u8 *)val);
	break;
	}
}

static void pci_write_config(struct pci_dev *pcidev,
			     void *val, size_t count, loff_t pos)
{
	switch(count) {
	case 4:
	pci_write_config_dword(pcidev, pos, *(u32 *)val);
	break;
	case 2:
	pci_write_config_word(pcidev, pos, *(u16 *)val);
	break;
	case 1:
	pci_write_config_byte(pcidev, pos, *(u8 *)val);
	break;
	}
}

static int find_dvsec(struct pci_dev *dev, int dvsec_id)
{
	int vsec = 0;
	u16 vendor, id;

	while ((vsec = pci_find_next_ext_capability(dev, vsec,
						    OCXL_EXT_CAP_ID_DVSEC))) {
		pci_read_config_word(dev, vsec + OCXL_DVSEC_VENDOR_OFFSET,
				&vendor);
		pci_read_config_word(dev, vsec + OCXL_DVSEC_ID_OFFSET, &id);
		if (vendor == PCI_VENDOR_ID_IBM && id == dvsec_id)
			return vsec;
	}
	return 0;
}

static u16 add_dvsec(struct pci_dev *pcidev, struct mdev_state *mdev_state,
		     int dvsec_id, u16 default_val) 
{
	u16 pos, next_cap_pos;

	pos = find_dvsec(pcidev, dvsec_id);
	if (!pos) {
		pr_debug("%s - Can't find dvsec id: %#x. Use default value\n",
			 __func__, dvsec_id);
		pos = default_val;
	}
	next_cap_pos = pos + CAPABILITY_SIZE;

	*(u32 *)&mdev_state->vconfig[pos] =
		PCI_EXT_CAP(OCXL_EXT_CAP_ID_DVSEC, 0x1, next_cap_pos);
	*(u32 *)&mdev_state->vconfig[pos + OCXL_DVSEC_VENDOR_OFFSET] = PCI_VENDOR_ID_IBM;
	*(u32 *)&mdev_state->vconfig[pos + OCXL_DVSEC_ID_OFFSET] = dvsec_id;

	return pos;
}

static void create_config_space(struct mdev_state *mdev_state)
{
	struct pci_dev *pcidev = to_pci_dev(mdev_state->fn->dev.parent);
	u16 pos, next_cap_pos;

	/* bar address */
	*(u32 *)&mdev_state->vconfig[PCI_BASE_ADDRESS_0] =
		   PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64;
	*(u32 *)&mdev_state->vconfig[PCI_BASE_ADDRESS_1] = 0x00000000;
	*(u32 *)&mdev_state->vconfig[PCI_BASE_ADDRESS_2] = 0x00000000;
	*(u32 *)&mdev_state->vconfig[PCI_BASE_ADDRESS_3] = 0x00000000;
	*(u32 *)&mdev_state->vconfig[PCI_BASE_ADDRESS_4] = 0x00000000;
	*(u32 *)&mdev_state->vconfig[PCI_BASE_ADDRESS_5] = 0x00000000;


	/* Process Address Space ID Extended Capability */
	pos = pci_find_ext_capability(pcidev, PCI_EXT_CAP_ID_PASID);
	if (!pos) {
		pr_debug("%s - Can't find PASID capability, use default value\n",
			 __func__);
		pos = PCI_CFG_SPACE_SIZE;
	}
	next_cap_pos = pos + CAPABILITY_SIZE;
	*(u32 *)&mdev_state->vconfig[pos] =
		PCI_EXT_CAP(PCI_EXT_CAP_ID_PASID, 0x1, next_cap_pos);
	*(u32 *)&mdev_state->vconfig[pos + OCXL_PASID_MAX_WIDTH] = 0x00000900;
	mdev_state->pasid_cap_pos = pos;
	pr_debug("%s - Process Address Space ID Extended Capability, pos: %#x\n",
		 __func__, mdev_state->pasid_cap_pos);

	/* Designated Vendor Specific Extended Capabilities - Transport Layer */
	pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_TL_ID, next_cap_pos);
	next_cap_pos = pos + CAPABILITY_SIZE;
	mdev_state->dvsec_tl_pos = pos;
	pr_debug("%s - DVSEC Transport Layer, pos: %#x\n",
		 __func__, mdev_state->dvsec_tl_pos);

	/* Designated Vendor Specific Extended Capabilities - Function Configuration */
	pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_FUNC_ID, next_cap_pos);
	next_cap_pos = pos + CAPABILITY_SIZE;
	*(u32 *)&mdev_state->vconfig[pos + OCXL_DVSEC_ID_OFFSET] |= (0x1 << 31);
	mdev_state->dvsec_fc_pos = pos;
	pr_debug("%s - Function Configuration, pos: %#x\n",
		 __func__, mdev_state->dvsec_fc_pos);

	/* Designated Vendor Specific Extended Capabilities - AFU Information */
	pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_AFU_INFO_ID, next_cap_pos);
	next_cap_pos = pos + CAPABILITY_SIZE;
	mdev_state->dvsec_info_pos = pos;
	pr_debug("%s - AFU Information, pos: %#x\n",
		 __func__, mdev_state->dvsec_info_pos);

	/* Designated Vendor Specific Extended Capabilities - AFU Control */
	pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_AFU_CTRL_ID, next_cap_pos);
	next_cap_pos = 0;
	*(u32 *)&mdev_state->vconfig[pos] =
		PCI_EXT_CAP(OCXL_EXT_CAP_ID_DVSEC, 0x1, next_cap_pos);
	mdev_state->dvsec_control_pos = pos;
	pr_debug("%s - AFU Control, pos: %#x\n",
		 __func__, pos);
}

static int ocxl_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct ocxl_fn *fn = to_ocxl_function(mdev_parent_dev(mdev));
	struct device *dev = mdev_dev(mdev);
	struct mdev_state *mdev_state;

	dev_dbg(dev, "Creating virtual OpenCAPI function %p\n", fn);

	mdev_state = kzalloc(sizeof(struct mdev_state), GFP_KERNEL);
	if (mdev_state == NULL)
		return -ENOMEM;

	mdev_state->vconfig = kzalloc(OCXL_MDEV_CONFIG_SPACE_SIZE, GFP_KERNEL);
	if (mdev_state->vconfig == NULL) {
		kfree(mdev_state);
		return -ENOMEM;
	}

	mdev_state->fn = fn;

	/* For the time being, only one afu is supported */

	/* Next step. Handle multiple AFU
	 * See p34 (Table 4-15. Example MMIO BAR Space Contents) of
	 * OpenCAPI_CFG_v05_081717.pdf
	 */
	mdev_state->afu = list_first_entry(&fn->afu_list, struct ocxl_afu, list);
	mdev_state->pp_mmio_ptr = ioremap(mdev_state->afu->pp_mmio_start,
					  mdev_state->afu->config.pp_mmio_stride * mdev_state->afu->pasid_max);
	if (!mdev_state->pp_mmio_ptr) {
		dev_err(dev, "Error mapping pp mmio area\n");
		return -ENOMEM;
	}
	mutex_init(&mdev_state->ops_lock);
	mdev_set_drvdata(mdev, mdev_state);

	create_config_space(mdev_state);

	return 0;
}

static int ocxl_mdev_remove(struct mdev_device *mdev)
{
	struct ocxl_fn *fn = to_ocxl_function(mdev_parent_dev(mdev));
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct device *dev = mdev_dev(mdev);

	dev_dbg(dev, "Removing virtual OpenCAPI function %p\n", fn);

	if (mdev_state->pp_mmio_ptr) {
		iounmap(mdev_state->pp_mmio_ptr);
		mdev_state->pp_mmio_ptr = NULL;
	}

	mdev_set_drvdata(mdev, NULL);
	kfree(mdev_state->vconfig);
	kfree(mdev_state);
	return 0;
}

static int ocxl_mdev_open(struct mdev_device *mdev)
{
	struct device *dev = mdev_dev(mdev);

	dev_dbg(dev, "%s\n", __func__);
	return 0;
}

static void ocxl_mdev_close(struct mdev_device *mdev)
{
	struct device *dev = mdev_dev(mdev);

	dev_dbg(dev, "%s\n", __func__);
}

static int handle_pci_cfg_write(struct mdev_device *mdev,
				void *val, size_t count, loff_t pos)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct pci_dev *pcidev = to_pci_dev(mdev_state->fn->dev.parent);
	struct device *dev = mdev_dev(mdev);
	int rc = 0, pasid;

	pr_debug("%s - count: %ld, pos: %#llx, val: %#x\n",
		 __func__, count, pos, *(u32 *)val);

	if (pos < PCI_CFG_SPACE_SIZE) {
		memcpy((mdev_state->vconfig + pos), val, count);
	}
	else if (pos == (mdev_state->dvsec_info_pos +
			 OCXL_DVSEC_AFU_INFO_OFF)) {
			pci_write_config(pcidev, val, count, pos);
	}
	else if (pos == (mdev_state->dvsec_control_pos +
			 OCXL_DVSEC_AFU_CTRL_TERM_PASID)) {
		pasid = *(u32 *)val & OCXL_DVSEC_PASID_MASK;
		pr_debug("%s - Terminate pasid: %d\n", __func__, pasid);

		rc = ocxl_config_terminate_pasid(pcidev,
						 mdev_state->dvsec_control_pos,
						 pasid);
		if (rc)
			dev_err(dev, "%s - Failed to terminate pasid, "
				     "pasid: %d (rc: %d)\n",
				     __func__, pasid, rc);
		else {
			rc = ocxl_link_remove_pe(mdev_state->fn->link,
						 pasid);
			if (rc)
				dev_err(dev, "%s - Failed to remove pe handle, "
					     "pasid: %d (rc: %d)\n",
					     __func__, pasid, rc);
		}

		*(u32 *)val &= ~(1<<20);
		memcpy((mdev_state->vconfig + pos), val, count);
	}
	else {
		memcpy((mdev_state->vconfig + pos), val, count);
	}

	return 0;
}

static int handle_pci_cfg_read(struct mdev_device *mdev,
			       void *val, size_t count, loff_t pos)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct pci_dev *pcidev = to_pci_dev(mdev_state->fn->dev.parent);
	int rc = 0;

#if 0
	pr_debug("%s - count: %ld, pos: %#llx\n", __func__, count, pos);
#endif

	switch (pos) {
	case 0 ... (PCI_CFG_SPACE_SIZE-1):
		if ((pos >= PCI_BASE_ADDRESS_0) &&
		    (pos <= PCI_BASE_ADDRESS_5)) {
			memcpy(val, (mdev_state->vconfig + pos), count);
		} else if (pos == PCI_ROM_ADDRESS) {
			memcpy(val, (mdev_state->vconfig + pos), count);
		} else {
			pci_read_config(pcidev, val, count, pos);
		}
	break;
	case PCI_CFG_SPACE_SIZE ... (OCXL_MDEV_CONFIG_SPACE_SIZE-1):
		if ((pos == mdev_state->pasid_cap_pos) ||
		    (pos == mdev_state->pasid_cap_pos + 0x4)||
		    (pos == mdev_state->pasid_cap_pos + 0x8)||
		    (pos == mdev_state->dvsec_tl_pos) ||
		    (pos == mdev_state->dvsec_tl_pos + 0x4)||
		    (pos == mdev_state->dvsec_tl_pos + 0x8)||
		    (pos == mdev_state->dvsec_fc_pos) ||
		    (pos == mdev_state->dvsec_fc_pos + 0x4)||
		    (pos == mdev_state->dvsec_fc_pos + 0x8)||
		    (pos == mdev_state->dvsec_info_pos) ||
		    (pos == mdev_state->dvsec_info_pos + 0x4)||
		    (pos == mdev_state->dvsec_info_pos + 0x8)||
		    (pos == mdev_state->dvsec_control_pos) ||
		    (pos == mdev_state->dvsec_control_pos + 0x4)||
		    (pos == mdev_state->dvsec_control_pos + 0x8))
			memcpy(val, (mdev_state->vconfig + pos), count);
		else
			pci_read_config(pcidev, val, count, pos);
	break;
	}

	return rc;
}

static int handle_bar_write(struct mdev_device *mdev,
			    void *val, size_t count, loff_t pos)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct device *dev = mdev_dev(mdev);
	struct ocxl_afu *afu;
	int pasid, offset, addr;
	u32 lpid = 0, pidr = 0, tidr = 0;
	int rc;

	addr = pos - OCXL_MDEV_BAR0_REGION_OFFSET;
	afu = mdev_state->afu;

	pr_debug("%s - count: %ld, pos: %#llx, addr: %#x, val: %#llx\n",
		 __func__, count, pos, addr, *(uint64_t *)val);

	/* Only one AFU is supported, for the time being */
	if ((addr >= afu->config.global_mmio_offset) &&
	    (addr < afu->config.global_mmio_offset + afu->config.global_mmio_size))
	{
		/* by pass - hcall attach from guest */
		offset = addr & 0xFF;
		if (offset == 0x30) {
			pasid = *(u32 *)val & OCXL_DVSEC_PASID_MASK;
			pidr = *(u32 *)val >> 20;
			lpid = 1;
			tidr = 0;
			pr_debug("%s - add pasid: %d (pidr: %#x)\n",
				 __func__, pasid, pidr);

			rc = ocxl_link_add_pe(mdev_state->fn->link,
					      pasid, lpid, pidr, tidr,
					      0, current->mm,
					      NULL, NULL);
			if (rc)
				dev_err(dev, "%s - Failed to add pe handle "
					     "pasid: %d (rc: %d)\n",
					__func__, pasid, rc);
		}
	}
	if ((addr >= afu->config.pp_mmio_offset) &&
	    (addr < (afu->config.pp_mmio_offset + 
		    (afu->config.pp_mmio_stride * afu->pasid_max))))
	{
		/* WED Register (x0000)
		 *     [63:12] Base EA of the start of the work element queue.
		 */
		pasid = (addr - afu->config.pp_mmio_offset) /
			 afu->config.pp_mmio_stride;
		offset = addr & 0xFF;
		pr_debug("%s - count: %ld, pos: %#llx, addr: %#x, pasid: %d, offset: %#x, val: %#llx\n",
			 __func__, count, pos, addr, pasid, offset, *(uint64_t *)val);

		out_le64(mdev_state->pp_mmio_ptr +
			 (afu->config.pp_mmio_stride * pasid) +
			 offset,
			 *(u64 *)val);
	}

	return 0;
}

static int handle_bar_read(struct mdev_device *mdev,
			   void *val, size_t count, loff_t pos)
{
	pr_debug("%s - count: %ld, pos: %#llx\n",
		 __func__, count, pos);

	*(u32 *)val = 0;

	return 0;
}

static ssize_t mdev_access(struct mdev_device *mdev, void *val,
			   size_t count, loff_t pos, bool is_write)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct device *dev = mdev_dev(mdev);
	int rc = 0;

	mutex_lock(&mdev_state->ops_lock);

	switch (pos) {
	case 0 ... (OCXL_MDEV_CONFIG_SPACE_SIZE-1):
		if (is_write)
			rc = handle_pci_cfg_write(mdev, val, count, pos);
		else
			rc = handle_pci_cfg_read(mdev, val, count, pos);
	break;
	/* Only one AFU is supported, for the time being */
	case OCXL_MDEV_BAR0_REGION_OFFSET ... (OCXL_MDEV_BAR0_REGION_OFFSET +
					       OCXL_MDEV_BAR0_REGION_SIZE):
		if (is_write)
			rc = handle_bar_write(mdev, val, count, pos);
		else
			rc = handle_bar_read(mdev, val, count, pos);
	break;
	default:
		dev_err(dev, "%s: @0x%llx (unhandled)\n",
			      __func__, pos);
		rc = -1;
	}

	mutex_unlock(&mdev_state->ops_lock);
	return rc;
}

static ssize_t ocxl_mdev_read(struct mdev_device *mdev,
			      char __user *buf, size_t count,
			      loff_t *ppos)
{
	unsigned int done = 0;
	int rc;

	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			rc =  mdev_access(mdev, (void *)&val, sizeof(val),
					  *ppos, false);
			if (rc < 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			rc = mdev_access(mdev, (void *)&val, sizeof(val),
					 *ppos, false);
			if (rc < 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			rc = mdev_access(mdev, (void *)&val, sizeof(val),
					 *ppos, false);
			if (rc < 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;

read_err:
	return -EFAULT;
}

static ssize_t ocxl_mdev_write(struct mdev_device *mdev,
			       const char __user *buf,
			       size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int rc;

	while (count) {
		size_t filled;

		if (count >= 8 && !(*ppos % 8)) {
			u64 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = mdev_access(mdev, &val, sizeof(val),
					 *ppos, true);
			if (rc < 0)
				goto write_err;

			filled = 8;
		} else if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = mdev_access(mdev, &val, sizeof(val),
					 *ppos, true);
			if (rc < 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = mdev_access(mdev, &val, sizeof(val),
					 *ppos, true);
			if (rc < 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = mdev_access(mdev, &val, sizeof(val),
					 *ppos, true);
			if (rc < 0)
				goto write_err;

			filled = 1;
		}
		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;
write_err:
	return -EFAULT;
}

static int get_device_info(struct mdev_device *mdev,
			   struct vfio_device_info *dev_info)
{
	dev_info->flags = VFIO_DEVICE_FLAGS_PCI;
	dev_info->num_regions = VFIO_PCI_NUM_REGIONS;
	dev_info->num_irqs = VFIO_PCI_NUM_IRQS;

	return 0;
}

static int get_region_info(struct mdev_device *mdev,
			   struct vfio_region_info *region_info,
			   u16 *cap_type_id, void **cap_type)
{
	switch (region_info->index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		region_info->offset = 0;
		region_info->size   = OCXL_MDEV_CONFIG_SPACE_SIZE;
		region_info->flags  = (VFIO_REGION_INFO_FLAG_READ |
				       VFIO_REGION_INFO_FLAG_WRITE);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
		region_info->offset = OCXL_MDEV_BAR0_REGION_OFFSET;
		region_info->size   = OCXL_MDEV_BAR0_REGION_SIZE;
		region_info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				       VFIO_REGION_INFO_FLAG_WRITE |
				       VFIO_REGION_INFO_FLAG_MMAP);
		break;
	default:
		region_info->size   = 0;
		region_info->offset = 0;
		region_info->flags  = 0;
	}

	return 0;
}

static int get_irq_info(struct mdev_device *mdev,
			struct vfio_irq_info *irq_info)
{
	irq_info->count = 0;
	return 0;
}

static long ocxl_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			   unsigned long arg)
{
	unsigned long minsz;
	int rc = 0;
	struct mdev_state *mdev_state;

	mdev_state = mdev_get_drvdata(mdev);

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
	{
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		rc = get_device_info(mdev, &info);
		if (rc)
			return rc;

		memcpy(&mdev_state->dev_info, &info, sizeof(info));

		return copy_to_user((void __user *)arg, &info, minsz);
	}
	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info;
		u16 cap_type_id = 0;
		void *cap_type = NULL;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		rc = get_region_info(mdev, &info, &cap_type_id,
				     &cap_type);
		if (rc)
			return rc;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_GET_IRQ_INFO:
	{
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if ((info.argsz < minsz) ||
		    (info.index >= mdev_state->dev_info.num_irqs))
			return -EINVAL;

		rc = get_irq_info(mdev, &info);
		if (rc)
			return rc;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	}

	return -ENOTTY;
}

static const struct mdev_parent_ops ocxl_mdev_ops = {
	.owner			= THIS_MODULE,
	.supported_type_groups	= mdev_type_groups,
	.create			= ocxl_mdev_create,
	.remove			= ocxl_mdev_remove,
	.open			= ocxl_mdev_open,
	.release		= ocxl_mdev_close,
	.read			= ocxl_mdev_read,
	.write			= ocxl_mdev_write,
	.ioctl			= ocxl_mdev_ioctl,
};

int ocxl_mdev_register(struct ocxl_fn *fn)
{
	dev_dbg(&fn->dev, "Registering OpenCAPI function %p %s\n", fn,
			  dev_name(&fn->dev));

	return mdev_register_device(&fn->dev, &ocxl_mdev_ops);
}

void ocxl_mdev_unregister(struct ocxl_fn *fn)
{
	dev_dbg(&fn->dev, "Unregistering OpenCAPI function %p %s\n", fn,
			  dev_name(&fn->dev));

	mdev_unregister_device(&fn->dev);
}
