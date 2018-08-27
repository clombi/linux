// SPDX-License-Identifier: GPL-2.0+
// Copyright 2017 IBM Corp.
#include <linux/module.h>
#include <linux/pci.h>
#include "ocxl_internal.h"

const struct ocxl_backend_ops *ocxl_ops;

static int __init init_ocxl(void)
{
	int rc = 0;

	rc = ocxl_file_init();
	if (rc)
		return rc;

	if (cpu_has_feature(CPU_FTR_HVMODE))
		ocxl_ops = &ocxl_native_ops;
#ifdef CONFIG_PPC_PSERIES
	else
		ocxl_ops = &ocxl_guest_ops;
#endif

	rc = pci_register_driver(&ocxl_pci_driver);
	if (rc) {
		ocxl_file_exit();
		return rc;
	}
	return 0;
}

static void exit_ocxl(void)
{
	pci_unregister_driver(&ocxl_pci_driver);
	ocxl_file_exit();
}

module_init(init_ocxl);
module_exit(exit_ocxl);

MODULE_DESCRIPTION("Open Coherent Accelerator");
MODULE_LICENSE("GPL");
