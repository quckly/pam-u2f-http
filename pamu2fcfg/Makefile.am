#  Copyright (C) 2014-2018 Yubico AB - See COPYING

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS=-I$(srcdir)/.. -I$(builddir)/.. $(LIBU2FSERVER_CFLAGS)

bin_PROGRAMS = pamu2fcfg

pamu2fcfg_SOURCES = pamu2fcfg.c
pamu2fcfg_SOURCES += cmdline.ggo cmdline.c cmdline.h  $(top_builddir)/util.c  $(top_builddir)/util.h
pamu2fcfg_LDADD = -lpam -ljansson -lcurl $(LIBU2FSERVER_LIBS)

cmdline.c cmdline.h: cmdline.ggo Makefile.am
	gengetopt --no-handle-help --input $^

BUILT_SOURCES = cmdline.c cmdline.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)
