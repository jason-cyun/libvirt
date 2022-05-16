#! /usr/bin/env bash
if [ "$#" -eq 1 ] && [ "$1" = "-r" ]; then
  make clean
  clangdinit intercept-build
else
  make CC=clang -j $(nproc)
fi

if [ $? -eq 0 ]; then
  make install

  echo "log_level = 1" >> /etc/libvirt/libvirtd.conf
  echo 'log_outputs="1:file:/var/log/libvirt/libvirtd.log"' >> /etc/libvirt/libvirtd.conf
  echo 'keepalive_interval=60' >> /etc/libvirt/libvirtd.conf
  echo 'admin_keepalive_interval=60' >> /etc/libvirt/libvirtd.conf

  echo 'listen_tls = 0' >> /etc/libvirt/libvirtd.conf
  echo 'listen_tcp = 1' >> /etc/libvirt/libvirtd.conf
  echo 'auth_tcp = "none"' >> /etc/libvirt/libvirtd.conf

  echo 'LIBVIRTD_ARGS="--listen"' >> /etc/sysconfig/libvirtd

  #echo 'uri_default = "qemu+tcp://127.0.0.1:16509/system"' >>/etc/libvirt/libvirt.conf
  systemctl daemon-reload
  service libvirtd restart
else
  echo "Failed to build"
fi
