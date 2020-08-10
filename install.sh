  
     #!/bin/bash
 
    set -e;
        
  # s    teps to prep your dev environment.

# supported and verified platforms
#    debian GNU/Linux10 (buster)

# right now p67 uses globally installed deps instead of local ones.

########
# ALSA #
########

# debian / ubuntu
sudo apt install libasound2-dev=1.1.8-1 -y;

###############
# opus codecs #
###############

# debian:
#   sudo apt install libopus-dev=1.3-1 libopusfile-dev=0.9+20170913-1
# ubuntu 
#   sudo apt install libopus-dev=1.1.2-1ubuntu1 libopusfile-dev=0.9+20170913-1build1

###########
# OpenSSL #
###########

#   1.1.1d is supported
# debian
#   sudo apt install openssl=1.1.1d-0+deb10u3 -y;
# ubuntu
#   wget https://www.openssl.org/source/openssl-1.1.1d.tar.gz --no-check-certificate
#   cd /openssl-1.1.1d
#   ./config
#   make
#   sudo make install

# rnnoise
#git clone https://github.com/xiph/rnnoise.git
# ./autogen.sh
# ./configure
# make
# sudo make install
# and you can use header


#########
# libpq #
#########

# for rserver

sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
sudo wget http://apt.postgresql.org/pub/repos/apt/ACCC4CF8.asc
sudo apt-key add ACCC4CF8.asc
#wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
sudo apt-get update
sudo apt-get install postgresql-12

sudo apt install libpq-dev postgresql-server-dev-all

# after that one may run
#   bash build.sh
