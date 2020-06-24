# build everything into <project_dir>/bin directory

set -e;

WD=`realpath $0 | xargs dirname`/

FP="$WD/lib"

FILES=`find $FP -name "*.c"`;

rm -fr $WD/bin
mkdir $WD/bin

DEBUG="-D DEBUG -g -fsanitize=address";

# build so

LIB=$WD/bin/libp67.so
EXE=$WD/bin/p67test

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
    -shared -o $LIB -fPIC;

# install library

sudo cp $LIB /usr/local/lib/;

sudo mkdir -p /usr/include/p67;

sudo cp $FP/*.h /usr/include/p67;

sudo ldconfig;

# build executable

FP="$WD/test"
FILES=`find $FP -name "*.c"`;

gcc $FILES $DEBUG -std=c99 -lp67 -o $EXE -W -g;
    
bash $WD/devcert.sh $WD;
