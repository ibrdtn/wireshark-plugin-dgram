#!/bin/sh

set -x

LANG=C
rm -rf autom4te.cache

autoreconf -i

