#!/usr/bin/env bash
virsh migrate --live --p2p --timeout 300 vm100 qemu+tcp://172.17.0.3:16509/system --verbose --copy-storage-all
