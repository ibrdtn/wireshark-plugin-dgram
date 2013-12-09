pluginsdir = $(WIRESHARK_PLUGINS_DIR)
plugins_LTLIBRARIES=dgram.la

AM_CPPFLAGS = -I$(top_srcdir)/src $(GLIB2_CFLAGS) $(WIRESHARK_CFLAGS)
AM_LDFLAGS = $(GLIB2_LIBS) $(WIRESHARK_LIBS)

dgram_la_LDFLAGS = -rpath $(pluginsdir) -avoid-version -module
dgram_la_SOURCES = \
	packet-dgram.h \
	packet-dgram.c \
	plugin.c \
	\
	$(NULL)
dgram_la_LIBADD = $(LDADDS)

