#!/usr/bin/env bash
/bin/rm -rf build/

# configure
meson build -Dprefix=/usr -Ddriver_vmware=disabled  -Ddriver_esx=disabled -Ddriver_qemu=enabled -Ddriver_libvirtd=enabled -Ddriver_remote=enabled  -Ddriver_lxc=disabled -Ddriver_vbox=disabled -Ddriver_openvz=disabled

# build and install
meson install -C build

# uninstall
# cd build && ninja uninstall
