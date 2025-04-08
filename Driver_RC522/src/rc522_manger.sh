#!/bin/sh -x

module="rc522_driver"
device="rc522"
rc522_dtbo="rc522-overlay.dtbo"
mode="666"
group=0

build() {
    make || error_exit "Failed to make the module file."
    # exit 0
}

db_install() {
    chmod +x $rc522_dtbo
    chown root:root $rc522_dtbo
	cp $rc522_dtbo /boot/firmware/overlays/
	cp $rc522_dtbo /boot/overlays/
}

load() {
    insmod ./$module.ko $* || exit 1

    chgrp $group /dev/$device
    chmod $mode /dev/$device
}

unload() {
    rm -f /dev/${device}
    rmmod $module || exit 1
}

# arg=${1:-"load"}
arg=$1
case $arg in
    build)
        build ;;
    install)
        db_install ;;
    load)
        load ;;
    unload)
        unload ;;
    reload)
        ( unload )
        load
        ;;
    *)
        build
        db_install
        ( unload )
        load
        ;;
esac
