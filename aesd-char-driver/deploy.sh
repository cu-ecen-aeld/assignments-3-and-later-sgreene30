#!/bin/sh
make clean
make

rm -rf /home/sgreene30/5assignment/base_external/rootfs_overlay/root/*
cp aesdchar_load /home/sgreene30/5assignment/base_external/rootfs_overlay/root/
cp aesdchar_unload /home/sgreene30/5assignment/base_external/rootfs_overlay/root/
cp aesdchar.ko /home/sgreene30/5assignment/base_external/rootfs_overlay/root/

