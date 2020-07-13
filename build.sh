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
    -shared -o $LIB -fPIC;

# install library

sudo cp $LIB /usr/local/lib/;

sudo mkdir -p /usr/include/p67;

sudo rm -f /usr/include/p67/*

sudo cp $FP/*.h /usr/include/p67;

sudo ldconfig;

# build tests

FP="$WD/test"

gcc-8 $FP/corenet.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67corenet -W -g $LOPENSSL $LALSA;
gcc-8 $FP/gencert.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67gencert -W -g $LOPENSSL $LALSA;
#gcc $FP/sound.c $FP/wav.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67sound -W -g $LOPENSSL $LALSA;
#gcc $FP/pudp.c $DEBUG -std=c99 -lp67 -o $WD/bin/p67pudp -W -g $LOPENSSL $LALSA;
gcc-8 $FP/opus.c $DEBUG $FP/wav.c -std=c99 -lp67 -o $WD/bin/p67opus -W -g $LOPENSSL $LALSA $OPUS;
gcc-8 $FP/wrtc.c $DEBUG $FP/wav.c -std=c99 -lp67 -o $WD/bin/p67wrtc -W -g $LOPENSSL $LALSA $OPUS;

bash $WD/devcert.sh $WD;
