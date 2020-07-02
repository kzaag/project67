# build everything into <project_dir>/bin directory

set -e;

WD=`realpath $0 | xargs dirname`/

FP="$WD/lib"

FILES=`find $FP -name "*.c" ! -name "__*"`;

rm -fr $WD/bin
mkdir $WD/bin

DEBUG="-D DEBUG -g -fsanitize=address";

# build so

LIB=$WD/bin/libp67.so

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
    -Wno-nonnull-compare  \
    `pkg-config --libs openssl` \
    `pkg-config --libs alsa` \
    $FILES \
    $DEBUG \
    -shared -o $LIB -fPIC;

# install library

sudo cp $LIB /usr/local/lib/;

sudo mkdir -p /usr/include/p67;

sudo rm -f /usr/include/p67/*

sudo cp $FP/*.h /usr/include/p67;

sudo ldconfig;

# build tests

FP="$WD/test"

gcc $FP/corenet.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67corenet -W -g;
gcc $FP/gencert.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67gencert -W -g;
gcc $FP/wrtc.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67wrtc -W -g `pkg-config --libs alsa`

bash $WD/devcert.sh $WD;
