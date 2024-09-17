
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/kernel.h>

/* Match table for of_platform binding */
static const struct of_device_id skeleton_dt_ids[] = {
    { .compatible = "msft,memory-log" },
    { }
};
MODULE_DEVICE_TABLE(of, skeleton_dt_ids);

/* Probe function: called for each matching device in the DTS */
static int skeleton_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    const struct device_node *np = dev->of_node;
    u32 reg;

    pr_debug("called skeleton_probe\n");

    /* Read the 'reg' property from the device tree */
    if (of_property_read_u32(np, "reg", &reg)) {
        dev_err(dev, "Failed to get 'reg' property\n");
        return -EINVAL;
    }

    /* Print the reg property value to verify multiple instances */
    dev_info(dev, "Probing device with reg: 0x%x\n", reg);

    /* Initialize the hardware or resources for this instance here */

    return 0;  // Success
}

/* Remove function: called when device is removed */
static int skeleton_remove(struct platform_device *pdev)
{
    /* Clean up resources allocated during probe */

    dev_info(&pdev->dev, "Device removed\n");
    return 0;
}

/* Platform driver structure */
static struct platform_driver skeleton_driver = {
    .probe = skeleton_probe,
    .remove = skeleton_remove,
    .driver = {
        .name = "skeleton_driver",
        .of_match_table = skeleton_dt_ids,
    },
};

/* Module init function */
static int __init skeleton_init(void)
{
    int ret = platform_driver_register(&skeleton_driver); 
    pr_info("Skeleton initialization result: %d\n", ret);
    return ret;
}

/* Module exit function */
static void __exit skeleton_exit(void)
{
    platform_driver_unregister(&skeleton_driver);
}

module_init(skeleton_init);
module_exit(skeleton_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hayden Rinn");
MODULE_DESCRIPTION("Simple Platform Driver with Multiple Instances");
