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
    $LOPENSSL $LALSA \
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

gcc $FP/corenet.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67corenet -W -g $LOPENSSL $LALSA;
gcc $FP/gencert.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67gencert -W -g $LOPENSSL $LALSA;
gcc $FP/sound.c $FP/wav.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67sound -W -g $LOPENSSL $LALSA;
gcc $FP/wrtc.c $DEBUG $FP/wav.c -std=c99 -lp67 -o $WD/bin/p67wrtc -W -g $LOPENSSL $LALSA;

bash $WD/devcert.sh $WD;
