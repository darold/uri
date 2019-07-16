PostgreSQL uri data type extension
==================================

uri is a extension to add uri data type for postgresql,
it allows to insert data in uri format and provide all
functions to extract uri parts, validate and compare uris.
Some functions are provided to check if an uri exists,
check size and content-type of remote uri (using libcurl)
and local uri.

It has the following operators `=`, `<>`, `<`, `<=`, `>`, `>=`, `@>`
and `<@`.

uri columns can be indexed using btree and hash indexes.


Requirement
-----------

You will need git, automake, autoconf and libtool to install liburi. The uri extension also need
libcurl-dev: `apt-get install libcurl4-openssl-dev` or `yum install libcurl-openssl-devel`.

You need to install [liburi](https://github.com/bbcarchdev/liburi) to be able to compile the uri
extension. liburi is a simple interface for parsing URIs based on [uriparser](http://uriparser.sourceforge.net/).
To install it:

	git clone git://github.com/bbcarchdev/liburi.git
	cd liburi
	git submodule update --init --recursive
	autoreconf -i
	./configure --prefix=/usr/local/liburi
	make
	make check
	sudo make install

Extraction of mime type from a local file is done with the use of [libmagic](http://www.darwinsys.com/file/). libmagic
is found with all Linux or BSD like distributions and comes with the `file` command, you will be able to install the
development binary package using `apt-get install libmagic-dev` or `yum install file-devel` for example.


Building
--------

Use the following command to build and install the extension,
`pg_config` must be in found from your PATH environment variable.

	make
	sudo make install

To test the extension run:

	make installcheck

To use the extension in your database execute:

	CREATE EXTENSION uri;


Functions
---------

The extension provide some useful functions to access all parts of a URI
per RFC 3986.

- `uri_get_scheme(uri)` returns protocol part of uri as text
- `uri_get_auth(uri)` returns user part of uri as text
- `uri_get_host(uri)` returns host part of uri as text
- `uri_get_port(uri)` returns port part of uri as text
- `uri_get_portnum(uri)` returns port part uri as integer
- `uri_get_path(uri)` returns path part of uri as text
- `uri_get_query(uri)` returns query part of uri as text
- `uri_get_fragment(uri)` returns fragment part of uri as text

The following are two URI examples and their component parts:

         foo://example.com:8042/over/there?name=ferret#nose
         \_/   \______________/\_________/ \_________/ \__/
          |           |            |            |        |
       scheme     authority       path        query   fragment
          |   _____________________|__
         / \ /                        \
         urn:example:animal:ferret:nose

Other functions:

- `uri_get_str(uri)` returns uri as text
- `uri_is_absolute(uri)` returns true if uri is absolute
- `uri_is_absolute_path(uri)` returns true if uri path is absolute
- `uri_localpath_exists(uri)` returns true if uri exists as a regular local path (not symlink).
- `uri_remotepath_exists(uri)` returns true if uri exists as a remote url.
- `uri_path_exists(uri)` returns true if uri exists as a local regular path (not symlink) or remote url (local/remote is autodetected).
- `uri_localpath_content_type(uri)` returns the content_type of a local file using libmagic.
- `uri_remotepath_content_type(uri)` returns the content_type of a remote url.
- `uri_path_content_type(uri)` returns the content_type of the url (local/remote is autodetected).
- `uri_localpath_size(uri)` returns the size of a local regular file (not symlink).
- `uri_remotepath_size(uri)` returns the size of a remote url.
- `uri_path_size(uri)` returns the size of a local path (not symlink) or remote url (local/remote is autodetected).
- `uri_escape(text)` returns the encoded URL of the given string using [curl_easy_escape()](https://curl.haxx.se/libcurl/c/curl_easy_escape.html).
- `uri_unescape(text)` returns the decoded URL of the given string using [curl_easy_unescape()](https://curl.haxx.se/libcurl/c/curl_easy_unescape.html).

Normalization
------------

In all functions URIs are normalized as they are parsed.  Normalisation is performed according to section 6.2.2 of
RFC3986, and includes adjusting the case of any scheme, hostname and percent-encoded characters so as to be
consistent, as well as removing redundant components from the path (for example, a path of `/a/b/c/../d/../../e` will
be normalised to `/a/e`).

This also mean that this extension stores normalized URI and not the original string. For example:

	test_uri=# INSERT INTO t1 (url) VALUES ('file:///etc/postgresql/9.3/main/../../9.6/main/postgresql.conf');
	INSERT  0 1
	test_uri=# SELECT * FROM t1 WHERE url = 'file:///etc/postgresql/9.3/main/../../9.6/main/postgresql.conf';
	 id |                       url                       
	----+-------------------------------------------------
	  1 | file:///etc/postgresql/9.6/main/postgresql.conf
	test_uri=# SELECT * FROM t1 WHERE url = 'file:///etc/postgresql/9.6/main/postgresql.conf';
	 id |                       url                       
	----+-------------------------------------------------
	  1 | file:///etc/postgresql/9.6/main/postgresql.conf

If you want to retrieve the original value `file:///etc/postgresql/9.3/main/../../9.6/main/postgresql.conf`
this will not be possible anymore.

Mime type and size
------------------

Function `uri_localpath_content_type()`, `uri_localpath_exists()`, `uri_localpath_size()`, `uri_remotepath_content_type()`,
`uri_remotepath_exists()` and `uri_remotepath_size()` and so on meta function `uri_path_content_type()`, `uri_path_exists()`
and `uri_path_size()` return NULL on uri access failure. The error returned by libcurl or the operating
system you have to use your own script to test the URL. In the future this may change if users ask for a buildin
function to report URL access error, at now I can't find any reason to do that.

Function `uri_remotepath_exists()` returns true when HTTP code returned by libcurl < 400, false when HTTP code 404 is returned
and NULL otherwise (HTTP code >= 400).

Functions `uri_remotepath_content_type()` returns the content-type found by libcurl, NULL otherwise. A WARNING with the HTTP
error code is outputed on failure.

Function `uri_localpath_content_type()` returns the mime type of the file using libmagic, or the operating error message in
case of failure.



Operators
---------

- `=`   check that 2 uri data are equals
- `<>`  check that 2 uri data are different
- `<`   check that an uri is literally lower than an other
- `<=`  check that an uri is literally lower or equal than an other
- `>`   check that an uri is literally greater than an other
- `>=`  check that an uri is literally greater or equal than an other
- `@>`  check that left uri contains right uri
- `<@`  check that left uri is contained in right uri


Examples
--------


	CREATE EXTENSION uri;

	CREATE TABLE example (id integer, url uri);

	INSERT INTO example VALUES (1, 'http://pgcluu.darold.net/index.html#top');
	INSERT INTO example VALUES (2, 'file:///opt/git/uri/README');
	INSERT INTO example VALUES (3, 'http://mydomain.com/pub/../public/../index 1.html');
	INSERT INTO example VALUES (4, 'http://username:passwd@mydomain.com/pub/index.php?view=menu&detail=1');
	INSERT INTO example VALUES (5, 'http://192.168.1.1/');

	SELECT * FROM example WHERE url='http://192.168.1.1/';

	SELECT uri_get_scheme(url), uri_get_host(url1) FROM example;
	SELECT uri_get_auth(url), uri_get_port(url1) FROM example;
	SELECT uri_get_path(url), uri_get_query(url1) FROM example;
	SELECT uri_get_fragment(url) FROM example;

	SELECT * FROM example WHERE uri_get_path(url)='/index.html';
	SELECT * FROM example WHERE uri_get_path(url) ~ '.*index.php';

	SELECT * FROM example WHERE url @> '192.168.1.1';
	SELECT * FROM example WHERE '192.168.1.1' <@ url;

The following example URIs illustrate several URI schemes and
variations in their common syntax components:

	INSERT INTO example VALUES (1, 'ftp://ftp.is.co.za/rfc/rfc1808.txt');
	INSERT INTO example VALUES (2, 'http://www.ietf.org/rfc/rfc2396.txt');
	INSERT INTO example VALUES (3, 'ldap://[2001:db8::7]/c=GB?objectClass?one');
	INSERT INTO example VALUES (4, 'telnet://192.0.2.16:80/');
	INSERT INTO example VALUES (5, 'file:///etc/postgresql/9.4/main/postgresql.conf.dist');


Indexes
-------

It is possible to create btree or hash indexes on uri data type.

	CREATE INDEX test2_index_uri ON example USING btree(url uri_btree_ops);
	CREATE INDEX test1_index_uri ON example USING hash(url uri_hash_ops);

The operator classes `uri_btree_ops` and `uri_hash_ops` can be omitted as they
are used as default operator class for the uri data type. With these operator
classes, all URIs are normalized before they are compared. So if you search records
where uri `file:///etc/postgresql/9.3/main/../../9.6/main/postgresql.conf` is found
if will search for `file:///etc/postgresql/9.6/main/postgresql.conf` into the index
or the table if the index is not used.

Authors
-------

Gilles Darold
gilles@darold.net

License
-------

This extension is free software distributed under the PostgreSQL Licence.

	Copyright (c) 2015-2018, Gilles Darold


