# contrib/uri/Makefile

MODULE_big = uri
OBJS = uri.o 

EXTVER=$(shell grep "version" uri.control | awk -F'=' '{print $$2};' | sed "s/[ ']//g")
EXTENSION = uri
DATA = uri--${EXTVER}.sql
DATA = $(wildcard $(EXTENSION)--*.sql)

PG_CONFIG = pg_config

# Extract the major version number
PG_MAJORVERSION := $(shell $(PG_CONFIG) --version | sed -E -e 's/^[a-zA-Z ]*//' -e 's/\..*//')

REGRESS = uri
# Check if major version is greater than or equal to 18 change test output
ifeq ($(shell test $(PG_MAJORVERSION) -ge 18; echo $$?),0)
    REGRESS = uri18
endif

# Link against uriparser, libcurl and libmagic
LIBCURL_CONFIG = curl-config
SHLIB_LINK := $(shell $(LIBCURL_CONFIG) --libs) -lmagic -luriparser

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
