#!/usr/bin/env bash
virt-admin daemon-log-filters "1:*"
virt-admin daemon-log-outputs "1:file:/var/log/libvirt/libvirtd.log"

