// SPDX-License-Identifier: GPL-2.0
/*
 * OpenCAPI for VFIO devices
 *
 * Copyright IBM Corp. 2018
 *
 * Author(s): Greg Kurz <groug@kaod.org>
 */

#include <linux/vfio.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/mdev.h>
#include <linux/kvm_host.h>

#include "ocxl_internal.h"

static int dev_has_iommu_table(struct device *dev, void *data)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct pci_dev **ppdev = data;

	if (!dev)
		return 0;

	if (dev->iommu_group) {
		*ppdev = pdev;
		return 1;
	}

	return 0;
}

/* FIXME: this should be in drivers/iommu/iommu.c ? */
static struct pci_dev *iommu_group_to_pci_dev(struct iommu_group *group)
{
	struct pci_dev *pdev = NULL;
	int ret;

	/* No IOMMU group ? */
	if (!group)
		return NULL;

	ret = iommu_group_for_each_dev(group, &pdev, dev_has_iommu_table);
	if (!ret || !pdev)
		return NULL;

	return pdev;
}

long ocxl_vfio_ioctl(struct iommu_group *iommu_group, unsigned int cmd,
		     unsigned long arg)
{
	unsigned long minsz;
	struct pci_dev *pdev;
	struct mdev_device *mdev;

	if (cmd == VFIO_CHECK_EXTENSION) {
		if (arg == VFIO_OCXL)
			return 1;
		else
			return 0;
	}

	pdev = iommu_group_to_pci_dev(iommu_group);
	if (!pdev) {
		pr_err("%s: no PCI device\n", __func__);
		return -ENODEV;
	}

	mdev = mdev_from_dev(&pdev->dev);
	if (!mdev) {
		pr_err("%s: no mediated device\n", __func__);
		return -ENODEV;
	}

	if (cmd == VFIO_OCXL_OP) {
		struct vfio_ocxl_op op;

		minsz = offsetofend(struct vfio_ocxl_op, op);
		if (copy_from_user(&op, (void __user *)arg, minsz))
			return -EFAULT;
		if (op.argsz < minsz || op.flags)
			return -EINVAL;

		if (op.op == VFIO_OCXL_ATTACH) {
			struct kvm *kvm;
			int lpid;

			minsz = offsetofend(struct vfio_ocxl_op, attach.pidr);
			if (copy_from_user(&op, (void __user *)arg, minsz))
				return -EFAULT;
			if (op.argsz < minsz)
				return -EINVAL;

			kvm = vfio_get_kvm_from_iommu(iommu_group);
			if (!kvm)
				return -ENODEV;
			lpid = kvm->arch.lpid;
			kvm_put_kvm(kvm);

			return ocxl_mdev_attach_pasid(mdev, op.attach.pasid,
						      lpid, op.attach.pidr);
		}
	}

	return -ENOTTY;
}
EXPORT_SYMBOL_GPL(ocxl_vfio_ioctl);
