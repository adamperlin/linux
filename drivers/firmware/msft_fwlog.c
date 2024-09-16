// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020 Microsoft Corp. All Rights Reserved.
 * Author: apais@linux.microsoft.com (Allen Pais)
 *
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include <asm/setup.h>

static phys_addr_t fwlog_paddr;
static unsigned long fwlog_size;
static void *fwlog_vaddr;

/*
 * Parse out the memory and size. We look for
 * mem=address,size.
 */

static int __init fw_addr_setup(char *arg)
{
	char *p;

	if (!arg)
		return 0;

	p = strsep(&arg, ",");
	if ((!p) || !*p)
		goto out;
	if (kstrtoull(p, 0, &fwlog_paddr) < 0)
		return -EINVAL;

	p = strsep(&arg, "");
	if ((!p) || !*p)
		goto out;
	if (kstrtoul(p, 0, &fwlog_size) < 0)
		return -EINVAL;

	return 0;
out:
	fwlog_paddr = 0;
	fwlog_size = 0;
	return -1;

}
early_param("earlyelog", fw_addr_setup);

static ssize_t fw_log_read(struct file *file, struct kobject *kobj,
			   struct bin_attribute *bin_attr, char *buf,
			   loff_t off, size_t count)
{
	if (off >= fwlog_size)
		return -EINVAL;

	if (count > fwlog_size - off)
		count = fwlog_size - off;

	if (!count)
		return 0;

	memcpy(buf, fwlog_vaddr + off, count);

	return count;
}

static int fw_log_mmap(struct file *file, struct kobject *kobj,
		       struct bin_attribute *bin_attr,
		       struct vm_area_struct *vma)
{
	unsigned long len;

	len = vma->vm_end - vma->vm_start;

	if (len > fwlog_size) {
		pr_err("vm_end[%lu] - vm_start[%lu] [%lu] > mem-size[%lu]\n",
			vma->vm_end, vma->vm_start,
			len, fwlog_size);
		return -EINVAL;
	}

	/*  On ARM64/armv8, memory set by pgprot_noncached
	 *  can only be accessed with 8-byte (64-bit) alignment.
	 */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return remap_pfn_range(vma,
			       vma->vm_start,
			       PFN_DOWN(fwlog_paddr) >> PAGE_SHIFT,
			       len, vma->vm_page_prot);
}
static struct bin_attribute firmware_log_attr __ro_after_init = {
	.attr = {
		.name = "msft_fwlog",
		.mode = S_IRUGO,
	},
	.read = &fw_log_read,
	.mmap = &fw_log_mmap,
};

static int __init fwlog_drv_init(void)
{
	int ret = 0;

	if (fwlog_paddr) {
		ret = memblock_reserve(fwlog_paddr, fwlog_size);
		if (ret < 0) {
			pr_err("ERROR: reservation failed\n");
			goto err;
		}

		fwlog_vaddr = memremap(fwlog_paddr, fwlog_size, MEMREMAP_WB);
		if (!fwlog_vaddr) {
			pr_err("ERROR: memremap failed in msft_fwlog\n");
			ret = -ENOMEM;
			goto err_map;
		}
		firmware_log_attr.size = fwlog_size;
		ret = sysfs_create_bin_file(firmware_kobj, &firmware_log_attr);
		if (ret)
			goto err_sysfs;
	}
	return 0;

err_sysfs:
	memunmap(fwlog_vaddr);
err_map:
	memblock_phys_free(fwlog_paddr, fwlog_size);
err:
	fwlog_vaddr = NULL;
	return ret;
}

static void __exit fwlog_drv_exit(void)
{
	if (fwlog_vaddr) {
		memunmap(fwlog_vaddr);
		memblock_phys_free(fwlog_paddr, fwlog_size);
		sysfs_remove_bin_file(firmware_kobj, &firmware_log_attr);
	}
}

module_init(fwlog_drv_init);
module_exit(fwlog_drv_exit);

MODULE_AUTHOR("Allen Pais <apais@linux.microsoft.com>");
MODULE_DESCRIPTION("MSFT Firmware Log driver");
MODULE_LICENSE("GPL");
