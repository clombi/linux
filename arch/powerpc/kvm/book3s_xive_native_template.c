/*
 * Copyright (c) 2017-2018, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

/* File to be included by other .c files */

#define XGLUE(a, b) a##b
#define GLUE(a, b) XGLUE(a, b)

/*
 * TODO: introduce a common template file with the XIVE native layer
 * and the XICS-on-XIVE glue for the utility functions
 */
static u8 GLUE(X_PFX, esb_load)(struct xive_irq_data *xd, u32 offset)
{
	u64 val;

	if (xd->flags & XIVE_IRQ_FLAG_SHIFT_BUG)
		offset |= offset << 4;

	val = __x_readq(__x_eoi_page(xd) + offset);
#ifdef __LITTLE_ENDIAN__
	val >>= 64-8;
#endif
	return (u8)val;
}
