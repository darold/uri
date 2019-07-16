# contrib/uri/Makefile

MODULE_big = uri
OBJS = uri.o 

EXTENSION = uri
DATA = uri--1.1.0.sql

REGRESS = uri

# add include and library paths for liburi
LIBURI_CONFIG = /usr/local/bin/liburi-config
LIBCURL_CONFIG = curl-config
PG_CPPFLAGS := $(shell $(LIBURI_CONFIG) --cflags)
SHLIB_LINK := $(shell $(LIBURI_CONFIG) --libs) $(shell $(LIBCURL_CONFIG) --libs) -lmagic

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

