// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020 Microsoft Corp. All Rights Reserved.
 * Author: apais@linux.microsoft.com (Allen Pais)
 * Author: haydenrinn@microsoft.com (Hayden Rinn)
 * Author: adamperlin@microsoft.com (Adam Perlin)
 */

#include "linux/kernfs.h"
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include <asm/setup.h>

#define EARLYELOG_FILENAME "msft_fwlog"
#define LOG_FILENAME "log"
#define SIG_FILENAME "signature"

#define DT_MAP_CACHED false
#define EARLYELOG_MAP_CACHED true

#define FW_LOG_SIGNATURE_LEN 4

#define IS_EARLYELOG() (earlyelog_paddr != 0)

struct fw_log_device_data {
	void *addr;
	phys_addr_t paddr;
	unsigned long long size;
	bool map_cached;
	const char *name;
	const char *signature;
	struct bin_attribute log_attr;
	struct kobj_attribute sig_attr;
};

static phys_addr_t earlyelog_paddr = 0;
static unsigned long long earlyelog_size = 0;
static struct platform_device *earlyelog_pdev = NULL;
static struct resource earlyelog_resources[] = {};
static struct kernfs_node *earlyelog_link_kn = NULL;

static const struct platform_device_id fw_log_id_table[] = { { "earlyelog", 0 },
							     {} };

static const struct of_device_id fw_log_dt_ids[] = {
	{ .compatible = "msft,memory-log" },
	{}
};
MODULE_DEVICE_TABLE(of, fw_log_dt_ids);

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
	if (kstrtoull(p, 0, &earlyelog_paddr) < 0)
		return -EINVAL;

	p = strsep(&arg, "");
	if ((!p) || !*p)
		goto out;
	if (kstrtoull(p, 0, &earlyelog_size) < 0)
		return -EINVAL;

	return 0;
out:
	earlyelog_paddr = 0;
	earlyelog_size = 0;
	return -1;
}
early_param("earlyelog", fw_addr_setup);

/* Parses msft,memory-log nodes for address, size, and log name */
static int parse_dt_node(struct device_node *np, struct device *dev,
			 struct fw_log_device_data *dev_data)
{
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

	dev_data->paddr = of_read_number(reg, addr_cells);
	reg += addr_cells;
	dev_data->size = of_read_number(reg, size_cells);

	dev_data->name = of_get_property(np, "label", &len);
	if (!dev_data->name) {
		dev_err(dev, "Failed to read 'label' property\n");
		return -EINVAL;
	}

	dev_data->signature = of_get_property(np, "signature", &len);
	if (dev_data->signature) {
		dev_err(dev, "Failed to read 'signature' property\n");
		return -EINVAL;
	}

	return 0;
}

static ssize_t fw_log_read(struct file *file, struct kobject *kobj,
			   struct bin_attribute *bin_attr, char *buf,
			   loff_t off, size_t count)
{
	struct device *dev;
	struct fw_log_device_data *dev_data;

	dev = container_of(kobj, struct device, kobj);
	dev_data = dev_get_drvdata(dev);
	if (!dev_data) {
		return -EFAULT;
	}

	if (off >= dev_data->size)
		return -EINVAL;

	if (count > dev_data->size - off)
		count = dev_data->size - off;

	if (!count)
		return 0;

	memcpy(buf, dev_data->addr + off, count);

	return count;
}

static int fw_log_mmap(struct file *file, struct kobject *kobj,
		       struct bin_attribute *bin_attr,
		       struct vm_area_struct *vma)
{
	unsigned long len;
	struct device *dev;
	struct fw_log_device_data *dev_data;

	dev = container_of(kobj, struct device, kobj);
	dev_data = dev_get_drvdata(dev);
	if (!dev_data) {
		return -EFAULT;
	}

	len = vma->vm_end - vma->vm_start;

	if (len > dev_data->size) {
		pr_err("vm_end[%lu] - vm_start[%lu] [%lu] > mem-size[%lu]\n",
		       vma->vm_end, vma->vm_start, len, dev_data->size);
		return -EINVAL;
	}

	/*  On ARM64/armv8, memory set by pgprot_noncached
	 *  can only be accessed with 8-byte (64-bit) alignment.
	 */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return remap_pfn_range(vma, vma->vm_start,
			       PFN_DOWN(dev_data->paddr) >> PAGE_SHIFT, len,
			       vma->vm_page_prot);
}

static void unmap_log_addr(void *addr, bool mapped_cached)
{
	if (mapped_cached) {
		memunmap(addr);
	} else {
		iounmap(addr);
	}
}

/* create_fwlog: Creates a memory-mapped firmware log file in the sysfs
 * @arg1: Pointer to a struct fw_log_device_data. Function expects data->paddr,
 *        and data->size to be initialized.
 * @arg2: kobject to create the file on in the sysfs
 * @arg3: Name of the sysfs file to be created
 * @arg4: Toggles between mapping cached (memremap) and mapping uncached (ioremap)
 */
static int create_fwlog(struct fw_log_device_data *data, struct kobject *kobj,
			bool map_cached)
{
	int ret;

	if (map_cached) {
		data->addr = memremap(data->paddr, data->size, MEMREMAP_WB);
	} else {
		data->addr = ioremap(data->paddr, data->size);
	}

	if (!data->addr) {
		pr_err("ERROR: %s failed in msft_fwlog\n",
		       (map_cached) ? "memremap" : "ioremap");
		ret = -ENOMEM;
		goto err;
	}

	/* Init log_attr */
	data->log_attr = (struct bin_attribute) {
		.attr = {
		 	.name = LOG_FILENAME,
		 	.mode = S_IRUGO,
		},
		.read = &fw_log_read,
		.mmap = &fw_log_mmap,
		.size = data->size,
	};

	ret = sysfs_create_bin_file(kobj, &data->log_attr);
	if (ret)
		goto err_sysfs;

	return 0;

err_sysfs:
	unmap_log_addr(data->addr, map_cached);
err:
	return ret;
}

static ssize_t sig_show(struct kobject *kobj, struct kobj_attribute *kobj_attr,
			char *buf)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct fw_log_device_data *dev_data = dev_get_drvdata(dev);

	if (!dev_data) {
		return -EFAULT;
	}

	if (dev_data->signature != NULL) {
		return snprintf(buf, FW_LOG_SIGNATURE_LEN + 1, "%s",
				dev_data->signature);
	}
	return 0;
}

static int create_fwlog_signature(struct fw_log_device_data *data,
				  struct kobject *kobj, char *name)
{
	int ret;

	/* Init sig_attr */
	data->sig_attr = (struct kobj_attribute) {
		.attr = {
			.name = name,
			.mode = S_IRUGO,
		},
		.show = &sig_show,
	};

	ret = sysfs_create_file(kobj, &data->sig_attr.attr);
	if (ret) {
		return ret;
	}

	return 0;
}

/* Reads the 4 byte signature at the beginning of a memory log, returning the data in a char buffer */
static inline void get_signature(void *addr, char *sig)
{
	u32 data = readl(addr);
	*((u32 *)sig) = data;
	sig[4] = '\0';
}

static void validate_fwlog_signature(struct device *dev,
				     struct fw_log_device_data *data)
{
	char sig[FW_LOG_SIGNATURE_LEN + 1];

	if (!data->signature) {
		dev_warn(dev, "%s: no signature defined in device tree\n",
			 __func__);
		return;
	}

	get_signature(data->addr, (char *)sig);
	if (strncmp(data->signature, sig, FW_LOG_SIGNATURE_LEN)) {
		pr_warn("%s: found invalid log signature: '%s', expected: '%s'\n",
			__func__, sig, data->signature);
	} else {
		pr_info("%s: found valid log signature: '%s'\n", __func__, sig);
	}
}

static int fw_log_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct fw_log_device_data *dev_data;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	int ret;

	/* Register node-specific data with the platform_device
	 * This memory is registered with the device and freed automatically
	 */
	dev_data = devm_kzalloc(dev, sizeof(struct fw_log_device_data),
				GFP_KERNEL);
	if (!dev_data) {
		ret = -ENOMEM;
		goto err;
	}
	platform_set_drvdata(pdev, dev_data);

	/* Fetch log parameters */
	if (np) {
		/* Device data is in device tree */
		if (parse_dt_node(np, dev, dev_data)) {
			dev_err(dev, "failed to parse DT node\n");
			ret = -EINVAL;
			goto err;
		}
		dev_data->map_cached = DT_MAP_CACHED;
	} else if (res) {
		/* Device data is in resources */
		dev_data->paddr = res->start;
		dev_data->size = (res->end - res->start);
		dev_data->name = res->name;
		dev_data->signature = NULL;
		dev_data->map_cached = EARLYELOG_MAP_CACHED;
	} else {
		dev_err(dev,
			"could not find parameters in device tree or resources\n");
		ret = -EINVAL;
		goto err;
	}

	dev_info(dev, "registering memory-log '%s' [0x%x - 0x%x)\n",
		 dev_data->name, dev_data->paddr,
		 dev_data->paddr + dev_data->size);

	/* Create log binfile */
	ret = create_fwlog(dev_data, &dev->kobj, dev_data->map_cached);
	if (ret) {
		dev_err(dev, "%s: failed to create fwlog sysfs file\n",
			__func__);
		goto err;
	}

	if (dev_data->signature) {
		/* Create signature file */
		validate_fwlog_signature(dev, dev_data);

		ret = create_fwlog_signature(dev_data, &dev->kobj,
					     SIG_FILENAME);
		if (ret) {
			dev_err(dev,
				"%s: failed to create fwlog signature sysfs file\n",
				__func__);
			goto err_sig;
		}
	}

	/* Link the device kobject into the firmware sysfs directory */
	ret = sysfs_create_link(firmware_kobj, &dev->kobj, dev_data->name);
	if (ret) {
		dev_err(dev,
			"%s: failed to create symlink to fwlog sysfs file in /sys/firmware\n",
			__func__);
		goto err_link;
	}

	return 0;

err_link:
	sysfs_remove_file(&dev->kobj, &dev_data->sig_attr.attr);
err_sig:
	unmap_log_addr(dev_data->addr, dev_data->map_cached);
	sysfs_remove_bin_file(&dev->kobj, &dev_data->log_attr);
err:
	return ret;
}

static int fw_log_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fw_log_device_data *dev_data = dev_get_drvdata(dev);

	if (dev_data && dev_data->addr) {
		unmap_log_addr(dev_data->addr, DT_MAP_CACHED);
		sysfs_remove_bin_file(&dev->kobj, &dev_data->log_attr);
		sysfs_remove_link(firmware_kobj, dev_data->name);
		if (dev_data->signature) {
			sysfs_remove_file(&dev->kobj, &dev_data->sig_attr.attr);
		}
	}

	dev_info(&pdev->dev, "Device removed\n");
	return 0;
}

/* Platform driver structure */
static struct platform_driver fw_log_driver = {
    .probe = fw_log_probe,
    .remove = fw_log_remove,
    .driver = {
        .name = "msft_fwlog",
        .of_match_table = fw_log_dt_ids,
    },
    .id_table = fw_log_id_table,
};

int create_msft_fwlog_symlink(struct platform_device *pdev)
{
	struct kernfs_node *log_kn, *firmware_kn;
	struct device *dev = &pdev->dev;
	int ret = 0;

	log_kn = kernfs_find_and_get(dev->kobj.sd, LOG_FILENAME);
	if (!log_kn) {
		dev_err(dev, "Failed to find kernfs node for log file\n");
		ret = -ENOENT;
		goto err;
	}

	firmware_kn = firmware_kobj->sd;
	if (!firmware_kn) {
		pr_err("Failed to find kernfs node for /sys/firmware\n");
		ret = -ENOENT;
		goto err;
	}

	earlyelog_link_kn = kernfs_create_link(firmware_kn, EARLYELOG_FILENAME, log_kn);
	if (IS_ERR(earlyelog_link_kn)) {
		pr_err("Failed to create symlink: /sys/firmware/%s\n",
		       EARLYELOG_FILENAME);
		earlyelog_link_kn = NULL;
		ret = -EINVAL;
		goto err;
	}

	kernfs_put(log_kn);
	return 0;

err:
	return ret;
}

static int __init fwlog_drv_init(void)
{
	int ret = 0;

	pr_info("%s: initializing MSFT FW log platform driver\n", __func__);
	ret = platform_driver_register(&fw_log_driver);
	if (ret) {
		pr_err("%s: failed to register FW log platform driver: %d\n",
		       __func__, ret);
		goto err;
	}

	if (earlyelog_paddr) {
		/* earlyelog is defined on command line. Manually register msft_fwlog platform device */
		pr_info("%s: initializing earlyelog platform device\n",
			__func__);

		earlyelog_resources[0] = (struct resource){
			.start = earlyelog_paddr,
			.end = earlyelog_paddr + earlyelog_size,
			.name = "elog",
			.flags = IORESOURCE_MEM,
		};

		earlyelog_pdev = platform_device_register_simple(
			"earlyelog", 0, earlyelog_resources, 1);

		ret = create_msft_fwlog_symlink(earlyelog_pdev);
		if (ret) {
			goto err;
		}
	}

	return 0;

err:
	return ret;
}

static void __exit fwlog_drv_exit(void)
{
	platform_driver_unregister(&fw_log_driver);
	if (earlyelog_link_kn) {
		kernfs_remove(earlyelog_link_kn);
	}
}

module_init(fwlog_drv_init);
module_exit(fwlog_drv_exit);

MODULE_AUTHOR("Allen Pais <apais@linux.microsoft.com>");
MODULE_AUTHOR("Hayden Rinn <haydenrinn@microsoft.com>");
MODULE_AUTHOR("Adam Perlin <adamperlin@microsoft.com>");
MODULE_DESCRIPTION("MSFT Firmware Log driver");
MODULE_LICENSE("GPL");
