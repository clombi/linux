// SPDX-License-Identifier: GPL-2.0+
// Copyright 2018 IBM Corp.
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <misc/ocxl-config.h>

#include "ocxl_internal.h"

#define VFIO_PCI_OFFSET_SHIFT   40
#define VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_INDEX_TO_OFFSET(index) ((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_MASK    (((u64)(1) << VFIO_PCI_OFFSET_SHIFT) - 1)

#define MDEV_DVSEC_PASID_MASK           GENMASK(19, 0)
#define MDEV_CONFIG_SPACE_SIZE          PCI_CFG_SPACE_EXP_SIZE
#define MDEV_CAPABILITY_SIZE            0x100
#define OCXL_MAX_AFU_PER_FUNCTION       64
#define MDEV_AFU_DESC_TEMPLATE_SIZE     0x58

#define OCXL_MMIO_PASID_REGISTER        0x50

#define EXTRACT_BIT(val, bit) (!!(val & BIT(bit)))
#define EXTRACT_BITS(val, s, e) ((val & GENMASK(e, s)) >> s)

#define PCI_EXT_CAP_VER_SHIFT      16
#define PCI_EXT_CAP_NEXT_SHIFT     20

#define PCI_EXT_CAP(id, ver, next)         \
    ((id) |                                \
     ((ver) << PCI_EXT_CAP_VER_SHIFT) |    \
     ((next) << PCI_EXT_CAP_NEXT_SHIFT))

#define CFG_TIMEOUT                3

#define MDEV_MAX_DEVICES           4
static u32 mdev_count;
static u8 mdev_index[MDEV_MAX_DEVICES];

/* State of each mdev device */
struct mdev_state {
	struct ocxl_fn *fn;
	struct mutex ops_lock;

	struct vfio_device_info dev_info;
	int max_dev_pasid;  /* max pasid per device */
	u8 index;           /* index number of the device: 0, 1, 2 or 3 */

	u8 *vconfig;        /* virtual PCI Config */
	u8 *vafudesc[OCXL_MAX_AFU_PER_FUNCTION]; /* virtual AFUs descriptor */

	u16 pasid_cap_pos;  /* Offset of PASID Capability */
	u16 dvsec_tl_pos;   /* Offset of the DVSEC - Transport Layer */
	u16 dvsec_fc_pos;   /* Offset of the DVSEC - Function Configuration */
	u16 dvsec_info_pos; /* Offset of the DVSEC - AFU information */
	u16 dvsec_control_pos; /* Offset of the DVSEC - AFU Control */

	struct ocxl_afu *afu;
	u8 afu_index;
	void __iomem *pp_mmio_ptr; /* iomap on afu pp mmio */
};

static int expFunc(unsigned int x)
{
	int exp;

	exp = 1 << x;
	return exp;
}

static int logFunc(unsigned int x)
{ 
	int log = -1;
	while(x) {
		log++;
		x >>= 1;
	}
	return log;
}

static int get_hw_pasid(struct mdev_state *mdev_state,
			int dev_pasid) 
{
	int hw_pasid;

	hw_pasid = (mdev_state->index * mdev_state->max_dev_pasid) +
		   dev_pasid;

	return hw_pasid;

}

int ocxl_mdev_attach_pasid(struct mdev_device *mdev, int pasid,
			   int lpid, int pidr)
{
	struct device *dev = mdev_dev(mdev);
	struct mdev_state *mdev_state;
	int rc, hw_pasid;

	mdev_state = mdev_get_drvdata(mdev);

	/* convert device pasid to hw pasid */
	hw_pasid = get_hw_pasid(mdev_state, pasid);

	dev_dbg(dev, "%s: hw_pasid=%d (dev pasid: %d) lpid=%d pidr=%d\n",
		     __func__, hw_pasid, pasid, lpid, pidr);
	rc = ocxl_link_add_pe(mdev_state->fn->link,
			      hw_pasid, lpid, pidr, 0,
			      0, current->mm,
			      NULL, NULL);
	if (rc)
		dev_err(dev, "%s - Failed to add pe handle "
			"hw_pasid=%d (dev pasid: %d) lpid: %d (rc: %d)\n",
			__func__, hw_pasid, pasid, lpid, rc);
	return rc;
}

static u16 find_dvsec(struct pci_dev *dev, int dvsec_id, u16 *last_pos)
{
	u16 vsec = 0, vendor, id;

	while ((vsec = pci_find_next_ext_capability(dev, vsec,
						    OCXL_EXT_CAP_ID_DVSEC))) {
		pci_read_config_word(dev, vsec + OCXL_DVSEC_VENDOR_OFFSET,
				&vendor);
		pci_read_config_word(dev, vsec + OCXL_DVSEC_ID_OFFSET, &id);
		if (vendor == PCI_VENDOR_ID_IBM && id == dvsec_id)
			return vsec;
		*last_pos = vsec;
	}
	return 0;
}

static u16 add_dvsec(struct pci_dev *pcidev,
		     struct mdev_state *mdev_state,
		     int dvsec_id) 
{
	u16 pos, last_pos = 0;

	pos = find_dvsec(pcidev, dvsec_id, &last_pos);
	if (pos)
		return pos;

	pos = last_pos + MDEV_CAPABILITY_SIZE;
	pr_debug("%s - Can't find dvsec id: %#x. Create a new entry, "
		 "pos: %#x, last_pos: %#x\n",
		 __func__, dvsec_id, pos, last_pos);
	*(u32 *)&mdev_state->vconfig[last_pos] =
		PCI_EXT_CAP(OCXL_EXT_CAP_ID_DVSEC, 0x1, pos);
	*(u32 *)&mdev_state->vconfig[pos] =
		PCI_EXT_CAP(OCXL_EXT_CAP_ID_DVSEC, 0x1, 0);
	*(u32 *)&mdev_state->vconfig[pos + OCXL_DVSEC_VENDOR_OFFSET] = PCI_VENDOR_ID_IBM;
	*(u32 *)&mdev_state->vconfig[pos + OCXL_DVSEC_ID_OFFSET] = dvsec_id;

	return pos;
}

static int read_afu_info(struct pci_dev *pcidev,
			 struct mdev_state *mdev_state,
			 int offset, u32 *data)
{
	u32 val;
	unsigned long timeout = jiffies + (HZ * CFG_TIMEOUT);
	int pos = mdev_state->dvsec_info_pos;

	pci_write_config_dword(pcidev, pos + OCXL_DVSEC_AFU_INFO_OFF, offset);
	pci_read_config_dword(pcidev, pos + OCXL_DVSEC_AFU_INFO_OFF, &val);
	while (!EXTRACT_BIT(val, 31)) {
		if (time_after_eq(jiffies, timeout))
			return -EBUSY;
		cpu_relax();
		pci_read_config_dword(pcidev, pos + OCXL_DVSEC_AFU_INFO_OFF, &val);
	}
	pci_read_config_dword(pcidev, pos + OCXL_DVSEC_AFU_INFO_DATA, data);
	return 0;
}

static int update_config_space(struct mdev_state *mdev_state)
{
	int pasid, pasid_pow, pos;
	u32 val32;
	u16 val16;
	u8 val8;

	/* Max PASID Width.
	 * This is the total for all AFUs associated with this Function
	 */
	pos = mdev_state->pasid_cap_pos + PCI_PASID_CAP;
	memcpy(&val16, mdev_state->vconfig + pos, sizeof(val16));
	pasid = expFunc(EXTRACT_BITS(val16, 8, 12));
	mdev_state->max_dev_pasid = pasid / MDEV_MAX_DEVICES;
	pasid_pow = logFunc(mdev_state->max_dev_pasid) / logFunc(2);

	val16 &= ~GENMASK(12, 8);
	val16 |= (pasid_pow << 8);
	memcpy(mdev_state->vconfig + pos, &val16, sizeof(val16));

	/* Number of consecutive PASID’s this AFU supports */
	pos = mdev_state->dvsec_control_pos + OCXL_DVSEC_AFU_CTRL_PASID_SUP;
	memcpy(&val8, mdev_state->vconfig + pos, sizeof(val8));
	pasid = expFunc(EXTRACT_BITS(val8, 0, 4));
	pasid_pow = logFunc(pasid / MDEV_MAX_DEVICES) / logFunc(2);

	val8 &= ~GENMASK(8, 0);
	val8 |= pasid_pow;
	memcpy(mdev_state->vconfig + pos, &val8, sizeof(val8));

	/* Number of consecutive PASID’s this AFU is allowed to use */
	pos = mdev_state->dvsec_control_pos + OCXL_DVSEC_AFU_CTRL_PASID_EN;
	memcpy(mdev_state->vconfig + pos, &val8, sizeof(val8));

	/* PASID Base, First PASID this AFU is allowed to use */
	pos = mdev_state->dvsec_control_pos + OCXL_DVSEC_AFU_CTRL_PASID_BASE;
	memcpy(&val32, mdev_state->vconfig + pos, sizeof(val32));
	val32 &= ~MDEV_DVSEC_PASID_MASK;
	val32 |= 0x0 & MDEV_DVSEC_PASID_MASK;
	memcpy(mdev_state->vconfig + pos, &val32, sizeof(val32));

	return 0;
}

static int create_config_space(struct mdev_state *mdev_state)
{
	struct pci_dev *pcidev = to_pci_dev(mdev_state->fn->dev.parent);
	int i, pos;
	u32 val;
	u8 afu;

	/* Copy the original pci config */
	for (i = 0; i < MDEV_CONFIG_SPACE_SIZE; i+=4) {
		pci_read_config_dword(pcidev, i, &val);
		memcpy(mdev_state->vconfig + i, &val, sizeof(val));
	}

	/* Designated Vendor Specific Extended Capabilities */
	mdev_state->pasid_cap_pos = pci_find_ext_capability(pcidev, PCI_EXT_CAP_ID_PASID);
	mdev_state->dvsec_tl_pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_TL_ID);
	mdev_state->dvsec_fc_pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_FUNC_ID);
	mdev_state->dvsec_info_pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_AFU_INFO_ID);
	mdev_state->dvsec_control_pos = add_dvsec(pcidev, mdev_state, OCXL_DVSEC_AFU_CTRL_ID);

	/* Copy the AFU Descriptor Template Data */
	pos = mdev_state->dvsec_info_pos;
	for (afu = 0; afu <= mdev_state->fn->config.max_afu_index; afu++) {
		pci_write_config_byte(pcidev,
				      mdev_state->dvsec_info_pos + 
				      OCXL_DVSEC_AFU_INFO_AFU_IDX,
				      afu);
		for (i = 0; i < MDEV_AFU_DESC_TEMPLATE_SIZE; i+=4) {
			read_afu_info(pcidev, mdev_state, i, &val);
			memcpy(mdev_state->vafudesc[afu] + i, &val, sizeof(val));
		}
	}

	return 0;
}

static int ocxl_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct ocxl_fn *fn = to_ocxl_function(mdev_parent_dev(mdev));
	struct device *dev = mdev_dev(mdev);
	struct mdev_state *mdev_state;
	int rc = 0, i;
	u8 afu;

	if (mdev_count >= MDEV_MAX_DEVICES) {
		dev_err(dev, "Failed to create virtual OpenCAPI "
			     "(Max devices (%d), reached\n",
			     MDEV_MAX_DEVICES);
		return -ENOMEM;
	}

	dev_dbg(dev, "Creating virtual OpenCAPI function %p\n", fn);

	mdev_state = kzalloc(sizeof(struct mdev_state), GFP_KERNEL);
	if (mdev_state == NULL)
		return -ENOMEM;

	mdev_state->vconfig = kzalloc(MDEV_CONFIG_SPACE_SIZE, GFP_KERNEL);
	if (mdev_state->vconfig == NULL) {
		kfree(mdev_state);
		return -ENOMEM;
	}
	mdev_state->fn = fn;

	for (afu = 0; afu <= fn->config.max_afu_index; afu++) {
		mdev_state->vafudesc[afu] = kzalloc(MDEV_AFU_DESC_TEMPLATE_SIZE,
						    GFP_KERNEL);
		if (mdev_state->vafudesc[afu] == NULL) {
			kfree(mdev_state->vconfig);
			kfree(mdev_state);
			return -ENOMEM;
		}
	}
	mdev_state->afu_index = 0;

	mdev_state->afu = list_first_entry(&fn->afu_list, struct ocxl_afu, list);
	mdev_state->pp_mmio_ptr = ioremap(mdev_state->afu->pp_mmio_start,
					  mdev_state->afu->config.pp_mmio_stride *
					  mdev_state->afu->pasid_max);
	if (!mdev_state->pp_mmio_ptr) {
		dev_err(dev, "Error mapping pp mmio area\n");
		return -ENOMEM;
	}

	mutex_init(&mdev_state->ops_lock);
	mdev_set_drvdata(mdev, mdev_state);

	rc = create_config_space(mdev_state);
	if (!rc)
		rc = update_config_space(mdev_state);

	if (!rc) {
		mdev_count++;
		for (i=0; i < MDEV_MAX_DEVICES; i++) {
			if (mdev_index[i] == 0) {
				mdev_index[i] = 1;
				mdev_state->index = i;
				break;
			}
		}
	}
	return rc;
}

static int ocxl_mdev_remove(struct mdev_device *mdev)
{
	struct ocxl_fn *fn = to_ocxl_function(mdev_parent_dev(mdev));
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct device *dev = mdev_dev(mdev);
	u8 afu;

	dev_dbg(dev, "Removing virtual OpenCAPI function %p\n", fn);

	if (mdev_state->pp_mmio_ptr) {
		iounmap(mdev_state->pp_mmio_ptr);
		mdev_state->pp_mmio_ptr = NULL;
	}

	mdev_index[mdev_state->index] = 0;
	mdev_set_drvdata(mdev, NULL);
	for (afu = 0; afu <= mdev_state->fn->config.max_afu_index; afu++)
		kfree(mdev_state->vafudesc[afu]);
	kfree(mdev_state->vconfig);
	kfree(mdev_state);

	mdev_count--;
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
	int rc = 0, pasid, hw_pasid;

	if (pos == mdev_state->dvsec_info_pos + OCXL_DVSEC_AFU_INFO_OFF)
		*(u32 *)val |= BIT(31);

	if (pos == mdev_state->dvsec_control_pos + OCXL_DVSEC_AFU_CTRL_TERM_PASID) {
		pasid = *(u32 *)val & MDEV_DVSEC_PASID_MASK;

		/* convert device pasid to hw pasid */
		hw_pasid = get_hw_pasid(mdev_state, pasid);

		rc = ocxl_config_terminate_pasid(pcidev,
						 mdev_state->dvsec_control_pos,
						 hw_pasid);
		if (rc)
			dev_err(dev, "%s - Failed to terminate pasid, "
				     "hw_pasid: %d (dev pasid: %d), (rc: %d)\n",
				     __func__, hw_pasid, pasid, rc);
		else {
			rc = ocxl_link_remove_pe(mdev_state->fn->link,
						 hw_pasid);
			if (rc)
				dev_err(dev, "%s - Failed to remove pe handle, "
					     "hw_pasid: %d (dev pasid: %d), "
					     "(rc: %d)\n",
					     __func__, hw_pasid, pasid, rc);
		}

		*(u32 *)val &= ~BIT(20);
	}

	memcpy(mdev_state->vconfig + pos, val, count);

	return 0;
}

static int handle_pci_cfg_read(struct mdev_device *mdev,
			       void *val, size_t count, loff_t pos)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	u8 afu_index = mdev_state->afu_index;
	u32 offset;

	if (pos == mdev_state->dvsec_info_pos + OCXL_DVSEC_AFU_INFO_DATA) {
		offset = mdev_state->vconfig[mdev_state->dvsec_info_pos +
			                     OCXL_DVSEC_AFU_INFO_OFF];
		offset &= 0x7ffffff;
		if (offset >= MDEV_AFU_DESC_TEMPLATE_SIZE)
			return -EINVAL;

		memcpy(val, mdev_state->vafudesc[afu_index] + offset, count);
	} else
		memcpy(val, mdev_state->vconfig + pos, count);

	return 0;
}

static void op_bar(void __iomem *addr, void *val, size_t count,
		   bool is_write)
{
	switch(count) {
	case 8:
		if (is_write)
			out_le64((u64 __iomem *)addr, *(u64 *)val);
		break;
	case 4:
		if (is_write)
			out_le32((u32 __iomem *)addr, *(u32 *)val);
		else
			*(u32 *)val = in_le32((u32 __iomem *)addr);
		break;
	case 2:
		if (is_write)
			out_le16((u16 __iomem *)addr, *(u16 *)val);
		else
			*(u16 *)val = in_le16((u16 __iomem *)addr);
		break;
	case 1:
		if (is_write)
			out_8((u8 __iomem *)addr, *(u8 *)val);
		else
			*(u8 *)val = in_8((u8 __iomem *)addr);
		break;
	}
}

static int handle_bar(struct mdev_device *mdev, void *val,
		      size_t count, loff_t pos, bool is_write)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct device *dev = mdev_dev(mdev);
	struct ocxl_afu *afu = mdev_state->afu;
	int pasid, hw_pasid;
	loff_t offset;
	int rc = 0;

	if ((pos >= afu->config.global_mmio_offset) &&
	    (pos < afu->config.global_mmio_offset +
		   afu->config.global_mmio_size)) {

		offset = pos - afu->config.global_mmio_offset;
		pr_debug("%s - %s, count: %ld, pos: %#llx, "
			 "offset: %#llx, val: %#llx\n",
			 __func__, is_write? "write": "read",
			 count, pos, offset, is_write? *(u64 *)val: 0);

		if (offset == OCXL_MMIO_PASID_REGISTER)
			*(u64 *)val |= get_hw_pasid(mdev_state, *(u64 *)val);

		op_bar(afu->global_mmio_ptr + offset, val, count, is_write);
	}
	else if ((pos >= afu->config.pp_mmio_offset) &&
		 (pos < (afu->config.pp_mmio_offset +
			(afu->config.pp_mmio_stride * afu->pasid_max)))) {

		pasid = (pos - afu->config.pp_mmio_offset) /
			 afu->config.pp_mmio_stride;
		offset = (pos - afu->config.pp_mmio_offset) -
			 (afu->config.pp_mmio_stride * pasid);

		/* convert device pasid to hw pasid */
		hw_pasid = get_hw_pasid(mdev_state, pasid);

		pr_debug("%s - %s, count: %ld, pos: %#llx, "
			 "hw_pasid: %d (dev pasid: %d), "
			 "offset: %#llx, val: %#llx\n",
			 __func__, is_write? "write": "read",
			 count, pos, hw_pasid, pasid,
			 offset, is_write? *(u64 *)val: 0);

		op_bar(mdev_state->pp_mmio_ptr +
		       (afu->config.pp_mmio_stride * hw_pasid) +
		       offset,
		       val, count, is_write);
	} else {
		dev_err(dev, "%s: @0x%llx (unhandled)\n",
			      __func__, pos);
		rc = -EINVAL;
	}

	return rc;
}

static ssize_t mdev_access(struct mdev_device *mdev, void *val,
			   size_t count, loff_t *ppos, bool is_write)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	uint64_t pos = *ppos & VFIO_PCI_OFFSET_MASK;
	struct device *dev = mdev_dev(mdev);
	int rc = 0;

	mutex_lock(&mdev_state->ops_lock);

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (is_write)
			rc = handle_pci_cfg_write(mdev,
						  val, count, pos);
		else
			rc = handle_pci_cfg_read(mdev,
						 val, count, pos);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
		rc = handle_bar(mdev, val, count, pos, is_write);
		break;
	default:
		dev_err(dev, "%s: @0x%llx (unhandled)\n",
			     __func__, pos);
		rc = -EINVAL;
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
					  ppos, false);
			if (rc < 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			rc = mdev_access(mdev, (void *)&val, sizeof(val),
					 ppos, false);
			if (rc < 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			rc = mdev_access(mdev, (void *)&val, sizeof(val),
					 ppos, false);
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
					 ppos, true);
			if (rc < 0)
				goto write_err;

			filled = 8;
		} else if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = mdev_access(mdev, &val, sizeof(val),
					 ppos, true);
			if (rc < 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = mdev_access(mdev, &val, sizeof(val),
					 ppos, true);
			if (rc < 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = mdev_access(mdev, &val, sizeof(val),
					 ppos, true);
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
			   struct vfio_region_info *info)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct pci_dev *pcidev = to_pci_dev(mdev_state->fn->dev.parent);

	switch (info->index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = MDEV_CONFIG_SPACE_SIZE;
		info->flags  = (VFIO_REGION_INFO_FLAG_READ |
				VFIO_REGION_INFO_FLAG_WRITE);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = pci_resource_len(pcidev, 0);
		info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				VFIO_REGION_INFO_FLAG_WRITE);
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = pci_resource_len(pcidev, 2);
		info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				VFIO_REGION_INFO_FLAG_WRITE);
		break;
	case VFIO_PCI_BAR4_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = pci_resource_len(pcidev, 4);
		info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				VFIO_REGION_INFO_FLAG_WRITE);
		break;
	default:
		info->size   = 0;
		info->offset = 0;
		info->flags  = 0;
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
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	unsigned long minsz;
	int rc = 0;

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

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		rc = get_region_info(mdev, &info);
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

static ssize_t name_show(struct kobject *kobj, struct device *dev,
			 char *buf)
{
	return sprintf(buf, "Virtual OpenCAPI adapter\n");
}
static MDEV_TYPE_ATTR_RO(name);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

static ssize_t available_instances_show(struct kobject *kobj,
					struct device *dev, char *buf)
{
	return sprintf(buf, "%d\n", MDEV_MAX_DEVICES - mdev_count);
}
MDEV_TYPE_ATTR_RO(available_instances);

static struct attribute *mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
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
