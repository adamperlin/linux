#!/bin/sh

busybox mount -t sysfs sysfs /sys

busybox insmod skeleton.ko
busybox rmmod skeleton.ko
busybox insmod msft_fwlog_v2.ko

busybox ls /sys/devices/platform
busybox ls -l /sys/firmware

busybox reboot -f
