m4_define([pkg_name],    [wireshark-plugin-dgram])
m4_define([pkg_version], [0.1.0])

AC_INIT(pkg_name, pkg_version)
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_SRCDIR(src/plugin.c)
AM_INIT_AUTOMAKE

# Test for new silent rules and enable only if they are available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CC_STDC

PKG_CHECK_MODULES(GLIB2, glib-2.0, [
  AC_SUBST(GLIB2_CFLAGS)
  AC_SUBST(GLIB2_LIBS)
])

WIRESHARK_PLUGINS_DIR="/usr/share/wireshark/plugins"
AC_SUBST(WIRESHARK_PLUGINS_DIR)

WIRESHARK_LIBS=""
WIRESHARK_CFLAGS="-I/usr/include/wireshark"
AC_SUBST(WIRESHARK_CFLAGS)
AC_SUBST(WIRESHARK_LIBS)

AC_CHECK_MEMBERS(
[fragment_items.hf_fragment_count, 
 fragment_items.hf_reassembled_length],[],[],
[[#include <glib.h>
  #include <epan/packet.h>
  #include <epan/reassemble.h>]])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_OUTPUT([
           Makefile
           src/Makefile
          ])

