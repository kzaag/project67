set -e;

FILES="net.c main.c err.c sfd.c hash.c";

DEBUG="-D DEBUG";

gcc \
    -std=c99 \
    -pthread \
    -D _GNU_SOURCE \
    -Wall \
    -Wextra \
    -Wpedantic \
    -pedantic \
    -Wmissing-prototypes \
    -Wstrict-prototypes \
    -Wold-style-definition \
    `pkg-config --libs openssl` \
    $FILES \
    $DEBUG \
    -o p67;
