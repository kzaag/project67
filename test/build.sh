set -e

# build test locally ( in this directory ) assuming libp67.so is already installed


HERE="."
BINPATH="$HERE/../bin/"

rm -rf $HERE/bin;
mkdir $HERE/bin;
FILES="$HERE/main.c"

gcc $FILES -W -fsanitize=address -std=c99 -lp67 -Wall -Wextra -Wpedantic -pedantic -g -D DEBUG -o $HERE/bin/p67test;

# copy crypto from bin
cp $BINPATH/ca_private_key $BINPATH/chain.pem $BINPATH/server_cert.pem $BINPATH/server_private_key $HERE/bin;
