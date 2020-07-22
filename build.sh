# build everything into <project_dir>/bin directory

set -e;

WD=`realpath $0 | xargs dirname`/

FP="$WD/lib"

FILES=`find $FP -name "*.c" ! -name "__*"`;

#rm -fr $WD/bin
mkdir -p $WD/bin

DEBUG="-D DEBUG -g -fsanitize=address";

LOPENSSL=`pkg-config --libs openssl`
LALSA=`pkg-config --libs alsa`
OPUS=`pkg-config --libs opus`
PULSEAUDIO="-lpulse -lpulse-simple"

# build so

LIB=$WD/bin/libp67.so

gcc-8 \
    -std=c99 \
    -pthread \
    -D _DEFAULT_SOURCE \
    -Wall \
    -Wextra \
    -Wpedantic \
    -pedantic \
    -Wmissing-prototypes \
    -Wstrict-prototypes \
    -Wold-style-definition \
    -Wno-nonnull-compare  \
    $LOPENSSL \
    $FILES \
    $DEBUG \
    $PULSEAUDIO \
    $OPUS \
    -shared -o $LIB -fPIC;

# install library

sudo cp $LIB /usr/local/lib/;

sudo mkdir -p /usr/include/p67;

sudo rm -f /usr/include/p67/*

sudo cp $FP/*.h /usr/include/p67;

sudo ldconfig;

# build tests

FP="$WD/test"

gcc-8 $FP/async.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67async $LOPENSSL;
gcc-8 $FP/net.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67net $LOPENSSL;
gcc-8 $FP/gencert.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67gencert $LOPENSSL;
gcc-8 $FP/pudp.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67pudp $LOPENSSL;
gcc-8 $FP/stream.c $DEBUG $FP/wav.c \
    -std=c99 -lp67 -o $WD/bin/p67stream $LOPENSSL $OPUS $PULSEAUDIO;

FP="$WD/rserver"
FILES=`find $FP -name "*.c" ! -name "__*"`;
LPQ=`pkg-config --libs libpq`;

gcc-8 \
    $FILES \
    -std=c99 \
    -pthread \
    -Wall \
    -Wextra \
    -Wpedantic \
    -pedantic \
    -Wmissing-prototypes \
    -Wstrict-prototypes \
    -Wold-style-definition \
    -Wno-nonnull-compare  \
    $DEBUG \
    $LOPENSSL \
    $LPQ \
    -lp67 \
    -o $WD/bin/p67rserver;

bash $WD/devcert.sh $WD;
