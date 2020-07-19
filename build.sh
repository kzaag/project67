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
    -D _GNU_SOURCE \
    -Wall \
    -Wextra \
    -Wpedantic \
    -pedantic \
    -Wmissing-prototypes \
    -Wstrict-prototypes \
    -Wold-style-definition \
    -Wno-nonnull-compare  \
    $LOPENSSL $LALSA \
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

gcc-8 $FP/async.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67async -W -g;
gcc-8 $FP/net.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67net -W -g $LOPENSSL;
gcc-8 $FP/gencert.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67gencert -W -g $LOPENSSL;
gcc-8 $FP/pudp.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67pudp -W -g $LOPENSSL

#gcc $FP/sound.c $FP/wav.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67sound -W -g $LOPENSSL $LALSA;
gcc-8 $FP/stream.c $DEBUG $FP/wav.c -std=c99 -lp67 -o $WD/bin/p67stream -W -g $LOPENSSL $OPUS $PULSEAUDIO;

bash $WD/devcert.sh $WD;
