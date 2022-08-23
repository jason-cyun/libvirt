#! /usr/bin/env bash
CC=clang  CFLAGS="-O0 -g" ./autogen.sh --system --with-bash-completion --with-phyp=no --with-openvz=no --with-uml=no --with-vmware=no --with-vbox=no --with-esx=no --with-dtrace=yes --enable-debug=yes

