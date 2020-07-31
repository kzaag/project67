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

# copy headers

echo "Installing headers"

sudo mkdir -p /usr/include/p67;

sudo rm -rf /usr/include/p67/*

cd $FP/;

HDRS=`find . -name "*.h" ! -name "__*"`;

sudo cp $HDRS --parents /usr/include/p67/;

cd - > /dev/null;

# build so

echo "Building library"

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

echo "Installing library"

sudo cp $LIB /usr/local/lib/;

sudo ldconfig;

# build tests

echo "Building tests"

FP="$WD/test"

mkdir -p $WD/bin/test;

echo "    async"
gcc-8 $FP/async.c $DEBUG -std=c99 -lp67 -o $WD/bin/test/async $LOPENSSL;
echo "    net"
gcc-8 $FP/net.c $DEBUG -std=c99 -lp67 -o $WD/bin/test/net $LOPENSSL;
echo "    gencert"
gcc-8 $FP/gencert.c $DEBUG -std=c99 -lp67 -o $WD/bin/test/gencert $LOPENSSL;
echo "    pdp"
gcc-8 $FP/pdp.c $DEBUG -std=c99 -lp67 -o $WD/bin/test/pdp $LOPENSSL;
#gcc-8 $FP/stream.c $DEBUG $FP/wav.c \
#    -std=c99 -lp67 -o $WD/bin/p67stream $LOPENSSL $OPUS $PULSEAUDIO;
echo "    rserver"
gcc-8 $FP/rserver.c $DEBUG -std=c99 -lp67 -o $WD/bin/test/rserver $LOPENSSL;

echo "Linking db files"

FP="$WD/rserver"
FILES=`find $FP -name "*.c" ! -name "__*"`;
LPQ=`pkg-config --libs libpq`;


ln -sf $FP/ddl $WD/bin/;
ln -sf $FP/main.conf.e $WD/bin/;

echo "Building rserver"

gcc-8 \
    $FILES \
    -std=c99 \
    -pthread \
    -Wall \
    -Wextra \
    -Wpedantic \
    -pedantic \
    -Wstrict-prototypes \
    -Wold-style-definition \
    -Wno-nonnull-compare  \
    $DEBUG \
    $LOPENSSL \
    $LPQ \
    -lp67 \
    -o $WD/bin/p67rserver;

echo "Generating certificates"

bash $WD/devcert.sh $WD;

echo "Done"

exit 0;