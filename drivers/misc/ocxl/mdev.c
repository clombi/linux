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

#include "ocxl_internal.h"

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

static int ocxl_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct ocxl_fn *fn = to_ocxl_function(mdev_parent_dev(mdev));

	pr_info("Creating virtual OpenCAPI function %p\n", fn);

	mdev_set_drvdata(mdev, fn);
	return 0;
}

static int ocxl_mdev_remove(struct mdev_device *mdev)
{
	struct ocxl_fn *fn = to_ocxl_function(mdev_parent_dev(mdev));

	pr_info("Removing virtual OpenCAPI function %p\n", fn);

	mdev_set_drvdata(mdev, NULL);
	return 0;
}

static int ocxl_mdev_open(struct mdev_device *mdev)
{
	pr_info("%s\n", __func__);
	return 0;
}

static void ocxl_mdev_close(struct mdev_device *mdev)
{
	pr_info("%s\n", __func__);
}

static long ocxl_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			   unsigned long arg)
{
	unsigned long minsz;

	if (cmd == VFIO_DEVICE_GET_INFO) {
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_PCI;
		info.num_regions = VFIO_PCI_NUM_REGIONS;
		info.num_irqs = 1;

		return copy_to_user((void __user *)arg, &info, minsz);
	}

	return -ENOTTY;
}

static const struct mdev_parent_ops ocxl_mdev_ops = {
	.owner                  = THIS_MODULE,
	.supported_type_groups  = mdev_type_groups,
	.create                 = ocxl_mdev_create,
	.remove                 = ocxl_mdev_remove,
	.open                   = ocxl_mdev_open,
	.release                = ocxl_mdev_close,
	.ioctl                  = ocxl_mdev_ioctl,
};

int ocxl_mdev_register(struct ocxl_fn *fn)
{
	pr_info("Registering OpenCAPI function %p %s\n", fn,
		dev_name(&fn->dev));

	return mdev_register_device(&fn->dev, &ocxl_mdev_ops);
}

void ocxl_mdev_unregister(struct ocxl_fn *fn)
{
	pr_info("Unregistering OpenCAPI function %p %s\n", fn,
		dev_name(&fn->dev));

	mdev_unregister_device(&fn->dev);
}
