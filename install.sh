#!/bin/bash

set -e;

# steps to prep your dev environment.

# supported and verified platforms
#    debian 9

# right now p67 uses globally installed deps instead of local ones.

# ALSA
sudo apt install libasound2-dev=1.1.8-1 -y;

# OpenSSL
sudo apt install openssl=1.1.1d-0+deb10u3 -y;

# then one can run
#   bash build.sh
