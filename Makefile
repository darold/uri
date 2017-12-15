# contrib/uri/Makefile

MODULE_big = uri
OBJS = uri.o 

EXTENSION = uri
DATA = uri--1.0.0.sql

REGRESS = uri

# add include and library paths for liburi
LIBURI_CONFIG = /usr/local/liburi/bin/liburi-config
LIBCURL_CONFIG = curl-config
PG_CPPFLAGS := $(shell $(LIBURI_CONFIG) --cflags)
SHLIB_LINK := $(shell $(LIBURI_CONFIG) --libs) $(shell $(LIBCURL_CONFIG) --libs) -lmagic

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/uri
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
