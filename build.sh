#!/bin/sh
# Build recent-screenshots-hider against the PS5 payload SDK (Linux/WSL
# build box).  Run ./build.sh from the repository root.

export PS5_PAYLOAD_SDK=${PS5_PAYLOAD_SDK:-/opt/ps5-payload-sdk}
export BUILD_VERSION=${BUILD_VERSION:-1.0}

make clean
make
