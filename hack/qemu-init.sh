#!/bin/sh

busybox mount -t sysfs sysfs /sys

# busybox insmod skeleton.ko
# busybox rmmod skeleton.ko
# busybox insmod msft_fwlog_v2.ko

busybox ls /sys/devices/platform
busybox ls -l /sys/firmware
busybox ls /sys/firmware/*log*

busybox echo "elog signature:"
busybox cat /sys/firmware/elog/signature

busybox echo "nmclog signature:"
busybox cat /sys/firmware/nmclog/signature

busybox reboot -f
