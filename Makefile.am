#  Copyright (C) 2014-2018 Yubico AB - See COPYING

SUBDIRS = . pamu2fcfg tests

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(CWFLAGS)
AM_CPPFLAGS = -I$(srcdir)/.. -I$(builddir)/.. $(LIBU2FSERVER_CFLAGS)

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_u2f_http.la

pam_u2f_http_la_SOURCES = pam-u2f-http.c
pam_u2f_http_la_SOURCES += util.c util.h

pam_u2f_http_la_LIBADD = -lpam -lcurl -ljansson
pam_u2f_http_la_LIBADD += $(LIBU2FSERVER_LIBS)
pam_u2f_http_la_LDFLAGS = -module -avoid-version

DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@

install-exec-hook:
	rm -f $(PAMDIR)/pam_u2f_http.la
	chmod -f 644 $(PAMDIR)/pam_u2f_http.so || true

indent:
	clang-format -i *.c *.h pamu2fcfg/pamu2fcfg.c

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

PROJECT = pam-u2f-http