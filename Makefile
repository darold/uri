# contrib/uri/Makefile

MODULE_big = uri
OBJS = uri.o 

EXTVER=$(shell grep "version" uri.control | awk -F'=' '{print $$2};' | sed "s/[ ']//g")
EXTENSION = uri
DATA = uri--${EXTVER}.sql
DATA = $(wildcard $(EXTENSION)--*.sql)

REGRESS = uri

# Link against uriparser, libcurl and libmagic
LIBCURL_CONFIG = curl-config
SHLIB_LINK := $(shell $(LIBCURL_CONFIG) --libs) -lmagic -luriparser

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
