#!/bin/sh

if [ "x$1" = "x" ]; then
    echo "usage: $0 version [--automatic]"
    exit
else
    VERSION="$1"
fi

if [ "x$2" = "x" ]; then
    COMMIT=HEAD
else
    COMMIT=$2
fi

WRKDIR=`pwd`

RELEASENAME="$(basename ${WRKDIR})-${VERSION}"

if [ -d $RELEASENAME ]; then
    echo "Deleting previous release named $RELEASENAME."
    rm -rf $WRKDIR/$RELEASENAME/
fi

echo "Making release named $RELEASENAME (commit $COMMIT)"

echo
echo "Building root: $RELEASENAME/"
git archive --prefix=$RELEASENAME/ $COMMIT | tar x
cd $RELEASENAME
autoconf
rm -rf autogen.sh autom4te.cache

# Run application specific instructions here.
if [ -x "$WRKDIR/application.sh" ]; then
	. $WRKDIR/application.sh
fi
if [ -x "$WRKDIR/scripts/application.sh" ]; then
	. $WRKDIR/scripts/application.sh
fi

cd ..

echo "Building $RELEASENAME.tbz2 from $RELEASENAME/"
tar jcf $RELEASENAME.tbz2 $RELEASENAME/

