// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2024 Microsoft Corp. All Rights Reserved.
 * Authors: haydenrinn@microsoft.com (Hayden Rinn)
 *          adamperlin@microsoft.com (Adam Perlin)
 *
 */

#include "linux/types.h"
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/memblock.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>

/* Match table for of_platform binding */
static const struct of_device_id fw_log_dt_ids[] = {
    { .compatible = "msft,memory-log" },
    { }
};
MODULE_DEVICE_TABLE(of, fw_log_dt_ids);

struct fw_log_device_data {
    void *addr;
    phys_addr_t paddr;
    u64 size;
    struct bin_attribute attr;
};

/* Implements interface for reading sysfs file */
static ssize_t fw_log_read(struct file *file, struct kobject *kobj,
			   struct bin_attribute *bin_attr, char *buf,
			   loff_t off, size_t count)
{
    struct device *dev = container_of(kobj, struct device, kobj);
    struct fw_log_device_data *dev_data = dev_get_drvdata(dev);
    
	if (off >= dev_data->size)
		return -EINVAL;

	if (count > dev_data->size - off)
		count = dev_data->size - off;

	if (!count)
		return 0;

	memcpy(buf, dev_data->addr + off, count);

	return count;
}

/* Implements interface for memory-mapping sysfs file */
static int fw_log_mmap(struct file *file, struct kobject *kobj,
		       struct bin_attribute *bin_attr,
		       struct vm_area_struct *vma)
{
	unsigned long len;
    struct device *dev = container_of(kobj, struct device, kobj);
    struct fw_log_device_data *dev_data = dev_get_drvdata(dev);

	len = vma->vm_end - vma->vm_start;

	if (len > dev_data->size) {
		pr_err("vm_end[%lu] - vm_start[%lu] [%lu] > mem-size[%lu]\n",
			vma->vm_end, vma->vm_start,
			len, dev_data->size);
		return -EINVAL;
	}

	/*  On ARM64/armv8, memory set by pgprot_noncached
	 *  can only be accessed with 8-byte (64-bit) alignment.
	 */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return remap_pfn_range(vma,
			       vma->vm_start,
			       PFN_DOWN(dev_data->paddr) >> PAGE_SHIFT,
			       len, vma->vm_page_prot);
}


static int parse_dt_node(struct device_node *np, struct device *dev, u64 *addr, u64 *size, const char **label) {
    int addr_cells, size_cells;
    int len;
    const __be32 *reg;

    addr_cells = of_n_addr_cells(np);
    size_cells = of_n_size_cells(np);

    reg = of_get_property(np, "reg", &len);
    if (!reg) {
        dev_err(dev, "Failed to read 'reg' property\n");
        return -EINVAL;
    }

    *addr = of_read_number(reg, addr_cells);
    reg += addr_cells;
    *size = of_read_number(reg, size_cells);

    *label = of_get_property(np, "label", &len);
    if (!label) {
        dev_err(dev, "Failed to read 'label' property\n");
        return -EINVAL;
    }

    return 0;
}

/* Probe function: called for each matching device in the DTS
 * 
 * Creates a sysfs bin file for each msft,memory-log compatible device
 */
static int fw_log_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct device_node *np = dev->of_node;
    const char *label;
    u64 addr, size;
    int ret;

    /* Register node-specific data with the platform_device */
    struct fw_log_device_data *dev_data;
    dev_data = devm_kzalloc(dev, sizeof(struct fw_log_device_data), GFP_KERNEL);
    if (!dev_data)
        return -ENOMEM;

    platform_set_drvdata(pdev, dev_data);

    /* Parse DT node */
    if (parse_dt_node(np, dev, &addr, &size, &label)) {
        dev_err(dev, "Failed to parse DT node\n");
        return -EINVAL;
    }

    dev_info(dev, "Probing memory-log device\n\taddr: 0x%x\n\tsize: 0x%x\n\tname: %s\n", addr, size, label);

    /* Map the memory_log into the address space */
    void *fwlog_vaddr = memremap(addr, size, MEMREMAP_WB);
    if (!fwlog_vaddr) {
        pr_err("%s: memremap failed", __func__);
        return -ENOMEM;
    }

    pr_info("%s: mapped %s to vaddr %p\n", __func__, label, fwlog_vaddr);

    dev_data->addr = fwlog_vaddr;
    dev_data->paddr = addr;
    dev_data->size = size;

    /* Create the sysfs bin file for the device */
    dev_data->attr = (struct bin_attribute) {
        .attr = {
            .name = label,
            .mode = S_IRUGO,
        },
        .read = &fw_log_read,
        .mmap = &fw_log_mmap,
        .size = size,
    };

    ret = sysfs_create_bin_file(firmware_kobj, &dev_data->attr);
    if (ret)
        pr_err("%s: failed to create sysfs bin file\n", __func__);
        return ret;

// use gotos to free devm and memunmap on errors

    return 0; 
}

/* Remove function: called when device is removed */
static int fw_log_remove(struct platform_device *pdev)
{
    /* Clean up resources allocated during probe */

    dev_info(&pdev->dev, "Device removed\n");
    return 0;
}




/* Platform driver structure */
static struct platform_driver fw_log_driver = {
    .probe = fw_log_probe,
    .remove = fw_log_remove,
    .driver = {
        .name = "msft_fwlog_v2",
        .of_match_table = fw_log_dt_ids,
    },
};

/* Module init function */
static int __init fw_log_init(void)
{
    int ret;

    if ((ret = platform_driver_register(&fw_log_driver))) {
        pr_err("%s: Failed to register FW log platform driver: %d\n", __func__, ret);
        return ret;
    }

    pr_info("%s: Registered FW log platform driver\n", __func__);
    return 0;
}

/* Module exit function */
static void __exit fw_log_exit(void)
{
    platform_driver_unregister(&fw_log_driver);
}

module_init(fw_log_init);
module_exit(fw_log_exit);

MODULE_AUTHOR("Adam Perlin <adamperlin@microsoft.com>");
MODULE_AUTHOR("Hayden Rinn <haydenrinn@microsoft.com>");
MODULE_DESCRIPTION("MSFT Firmware Log driver revision 2");
MODULE_LICENSE("GPL");
