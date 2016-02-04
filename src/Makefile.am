bin_PROGRAMS = sipgrep
#AM_CFLAGS = -g -fPIC -rdynamic -I$(top_srcdir)/src/include ${EXTRA_DEFINES}
#AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -I$(top_srcdir)/src/include
#sipgrep_LDADD = $(LIBOBJS)
sipgrep_SOURCES = sipgrep.c log.c ipreasm.c tcpreasm.c sipparse.c

if HAVE_HEP
sipgrep_SOURCES+=transport_hep.c
endif

if USE_NCURSES
sipgrep_SOURCES+=user_interface.c
endif

