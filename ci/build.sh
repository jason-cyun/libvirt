#!/bin/sh

cd "$CI_CONT_SRCDIR"

export VIR_TEST_DEBUG=1

# $MESON_OPTS is an env that can optionally be set in the container,
# populated at build time from the Dockerfile. A typical use case would
# be to pass options to trigger cross-compilation
#
# $MESON_ARGS correspond to meson's setup args, i.e. configure args. It's
# populated either from a GitLab's job configuration or from command line as
# `$ helper build --meson-configure-args=-Dopt1 -Dopt2` when run in a local
# containerized environment

MESON_ARGS="$MESON_ARGS $MESON_OPTS"

meson setup build --werror -Dsystem=true $MESON_ARGS || \
(cat build/meson-logs/meson-log.txt && exit 1)

ninja -C build $NINJA_ARGS
