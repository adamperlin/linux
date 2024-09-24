// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2024 Microsoft Corp. All Rights Reserved.
 * Authors: haydenrinn@microsoft.com (Hayden Rinn)
 *          adamperlin@microsoft.com (Adam Perlin)
 *
 */

#include "linux/device.h"
#include "linux/io.h"
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
#include <linux/string.h>

#define FW_LOG_SIGNATURE_LEN 4

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


/* Parses msft,memory-log nodes for address, size, log name, and log signature */
static int parse_dt_node(struct device_node *np, struct device *dev, u64 *addr, u64 *size, const char **label, const char **signature) {
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

    
    *signature = of_get_property(np, "signature", &len);
    if (!signature) {
        dev_err(dev, "Failed to read 'signature' property\n");
        return -EINVAL;
    }

    return 0;
}

/* Reads the 4 byte signature at the beginning of a memory log, returning the data in a char buffer */
static void get_signature(void *addr, char *sig) {
    u32 data = readl(addr);

    sig[0] = (char)(data & 0xFF);
    sig[1] = (char)((data >> 8) & 0xFF);
    sig[2] = (char)((data >> 16) & 0xFF);
    sig[3] = (char)((data >> 24) & 0xFF);
    sig[4] = '\0';
}

/* Creates memory-mapped sysfs bin files for each probed msft,memory-log device */
static int fw_log_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct device_node *np = dev->of_node;
    const char *label, *signature;
    u64 addr, size;
    char actual_sig[5];
    int ret;

    /* Register node-specific data with the platform_device */
    struct fw_log_device_data *dev_data;
    /* This memory is registered with the device and freed automatically */
    dev_data = devm_kzalloc(dev, sizeof(struct fw_log_device_data), GFP_KERNEL);
    if (!dev_data) {
        ret = -ENOMEM;
        goto err;
    }

    platform_set_drvdata(pdev, dev_data);

    /* Parse DT node */
    if (parse_dt_node(np, dev, &addr, &size, &label, &signature)) {
        dev_err(dev, "failed to parse DT node\n");
        ret = -EINVAL;
        goto err;
    }

    dev_info(dev, "registering memory-log '%s' [0x%x - 0x%x)\n", label, addr, addr + size);

    /* Map the memory_log into the address space */
    void *fwlog_vaddr = memremap(addr, size, MEMREMAP_WB);
    if (!fwlog_vaddr) {
        pr_err("%s: memremap failed", __func__);
        ret = -ENOMEM;
        goto err;
    }

    dev_data->addr = fwlog_vaddr;
    dev_data->paddr = addr;
    dev_data->size = size;

    /* Validate the memory log signature */
    get_signature(fwlog_vaddr, (char *)actual_sig);
    if (strncmp(signature, actual_sig, 4)) {
        #ifdef CONFIG_MSFT_FW_LOG_STRICT_SIG_CHECKS
            pr_err("%s: found invalid log signature: '%s', expected: '%s'\n", __func__, actual_sig, signature);
            ret = -EINVAL;
            goto err;
        #else
            pr_warn("%s: found invalid log signature: '%s', expected: '%s'\n", __func__, actual_sig, signature);
        #endif
    } else {
        pr_info("%s: found valid log signature: '%s'\n", __func__, actual_sig);
    }
    
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

    /* Create binfile in /sys/firmware for backwards compat with v1 */
    ret = sysfs_create_bin_file(firmware_kobj, &dev_data->attr);
    if (ret) {
        pr_err("%s: failed to create sysfs bin file\n", __func__);
        goto err_sysfs;
    }

    pr_info("%s: created sysfs bin file: %s\n", __func__, dev_data->attr.attr.name);

    return 0;

err_sysfs:
    memunmap(fwlog_vaddr);
err:
    return ret; 
}

/* Cleans up each platform device when that driver is unloaded */
static int fw_log_remove(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct fw_log_device_data *dev_data = dev_get_drvdata(dev);

    if (dev_data && dev_data->addr) {
        memunmap(dev_data->addr);
        sysfs_remove_bin_file(firmware_kobj, &dev_data->attr);
    }

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
        pr_err("%s: failed to register FW log platform driver: %d\n", __func__, ret);
        return ret;
    }

    pr_info("%s: registered FW log platform driver\n", __func__);
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
