# Module name
MODULE_NAME := rc522_driver

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := rc522_main.o rc522_api.o

CROSS_COMPILE := aarch64-linux-gnu-

# CROSS_COMPILE := aarch64-agl-linux-

# Kernel directory for the target architecture
# KDIR := ../../rpi/lib/modules/6.6.56-v8_BY_ABDO_DAOOD+/build/
KDIR := /lib/modules/$(shell uname -r)/build # Kernel directory for the target architecture

PWD := $(shell pwd)


all: module dt
	
module:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) modules
dt: rc522-overlay.dts
	dtc -@ -I dts -O dtb -o rc522-overlay.dtbo rc522-overlay.dts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) clean
	rm -rf rc522-overlay.dtbo
install:
	chmod +x rc522-overlay.dtbo
	cp rc522-overlay.dtbo /boot/firmware/overlays/
	cp rc522-overlay.dtbo /boot/overlays/
