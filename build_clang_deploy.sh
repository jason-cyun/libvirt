#! /usr/bin/env bash
if [ "$#" -eq 1 ] && [ "$1" = "-r" ]; then
  make clean
  clangdinit intercept-build
else
  make CC=clang -j "$(nproc)"
fi

if [ $? -eq 0 ]; then
  make install

  # echo "log_level = 3"
  # echo 'log_filters="1:qemu.qemu_domain"'
  {
    echo "log_level = 1"
    echo 'log_outputs="1:file:/var/log/libvirt/libvirtd.log"'
    echo 'keepalive_interval=60'
    echo 'admin_keepalive_interval=60'

    echo 'listen_tls = 0'
    echo 'listen_tcp = 1'
    echo 'tcp_port= "16509"'
    echo 'auth_tcp = "none"'
  } >> /etc/libvirt/libvirtd.conf

  echo 'LIBVIRTD_ARGS="--listen"' >> /etc/sysconfig/libvirtd

  #echo 'uri_default = "qemu+tcp://127.0.0.1:16509/system"' >>/etc/libvirt/libvirt.conf
  systemctl daemon-reload
  service libvirtd restart
else
  echo "Failed to build"
fi
