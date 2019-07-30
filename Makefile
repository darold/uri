# contrib/uri/Makefile

MODULE_big = uri
OBJS = uri.o 

EXTVER=$(shell grep "version" uri.control | awk -F'=' '{print $$2};' | sed "s/[ ']//g")
EXTENSION = uri
DATA = uri--${EXTVER}.sql

REGRESS = uri

# add include and library paths for liburi
LIBURI_CONFIG = $(shell which /usr/bin/liburi-config /usr/local/bin/liburi-config /usr/local/liburi/bin/liburi-config 2>/dev/null)
LIBCURL_CONFIG = curl-config
PG_CPPFLAGS := $(shell $(LIBURI_CONFIG) --cflags)
SHLIB_LINK := $(shell $(LIBURI_CONFIG) --libs) $(shell $(LIBCURL_CONFIG) --libs) -lmagic

ifdef NO_PGXS
subdir = contrib/uri
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
else
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
endif
