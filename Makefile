#
# $Id: Makefile.in,v 1.23 2006/11/28 13:35:37 jpr5 Exp $
#
# Copyright (c) 2006  Jordan Ritter <jpr5@darkridge.com>
#
# Please refer to the LICENSE file for more information.

CC=gcc

CFLAGS=-g -O2 -DLINUX -DHAVE_CONFIG_H  -D_BSD_SOURCE=1 -D__FAVOR_BSD=1 
INCLUDES=-I. -I/usr/include 

LDFLAGS= -L/usr/lib
LIBS=-lpcap  

STRIPFLAG=-s

SRC=sipgrep.c ipreasm.c sipparse.c
OBJS=sipgrep.o ipreasm.o sipparse.o
TARGET=sipgrep
MANPAGE=sipgrep.8

prefix      = /usr
exec_prefix = ${prefix}

bindir      = $(prefix)/bin
datadir     = $(prefix)/share
mandir      = $(datadir)/man

BINDIR_INSTALL = $(prefix)/bin
MANDIR_INSTALL = $(mandir)/man8

INSTALL = ./install-sh

REGEX_DIR=regex-0.12
REGEX_OBJS=regex-0.12/regex.o


all: $(TARGET) 

$(TARGET): $(REGEX_OBJS) $(OBJS) 
	$(CC) $(CFLAGS) $(LDFLAGS) $(STRIPFLAG) -o $(TARGET) $(OBJS) $(REGEX_OBJS) $(LIBS) 

debug: $(REGEX_OBJS) $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -g -o $(TARGET) $(OBJS) $(REGEX_OBJS) $(LIBS) 

static: $(REGEX_OBJS) $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(STRIPFLAG) -o $(TARGET).static -static $(OBJS) $(REGEX_OBJS) $(LIBS) 

install: $(TARGET)
	$(INSTALL) -c -m 0755 $(TARGET)  $(DESTDIR)/$(BINDIR_INSTALL)/$(TARGET)
	$(INSTALL) -c -m 0644 $(MANPAGE) $(DESTDIR)/$(MANDIR_INSTALL)/$(MANPAGE)

.c.o:	
	$(CC) $(CFLAGS) $(INCLUDES) -g -c $<

clean:
	make -C $(REGEX_DIR) clean
	rm -f *~ $(OBJS) $(REGEX_OBJS) $(TARGET) $(TARGET).static

distclean: clean 
	make -C $(REGEX_DIR) distclean
	rm -f config.status config.cache config.log config.h Makefile 

$(REGEX_OBJS): $(REGEX_OBJS:.o=.c) $(REGEX_DIR)/*.h
	$(MAKE) $(MAKEFLAGS) -C $(REGEX_DIR) $(notdir $(REGEX_OBJS))

$(OBJS): Makefile sipgrep.c sipgrep.h

tardist:
	@( VERSION=`perl -ne '/VERSION\s+"(.*)"/ && print "$$1\n"' sipgrep.h` ; \
	   PKG="sipgrep-$$VERSION"                                            ; \
	   TMPDIR="/tmp"                                                    ; \
	   DESTDIR="$$TMPDIR/$$PKG"                                         ; \
	   echo                                                             ; \
	   echo "Building package $$PKG ... "                               ; \
	   echo                                                             ; \
	   sleep 2                                                          ; \
	   rm -rf $$DESTDIR && mkdir $$DESTDIR                             && \
	   make distclean                                                  && \
	   tar cf - . --exclude "CVS" | tar xf - -C $$DESTDIR              && \
	   find $$DESTDIR -name "*~" -o -name ".*#*" | xargs rm -f         && \
	   cd $$TMPDIR && tar jcf $$PKG.tar.bz2 $$PKG                       ; \
           rm -rf $$DESTDIR                                                 ; \
           cd $$TMPDIR && gpg -ba $$PKG.tar.bz2                             ; \
	   echo                                                             ; \
	   ls -l $$TMPDIR/$$PKG.tar.bz2 $$TMPDIR/$$PKG.tar.bz2.asc          ; \
	   echo                                                             ; \
	)
