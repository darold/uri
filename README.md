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

Building
--------

Use the following commnand to build and install the extension,
pg_config must be in found from your PATH environment variable.

	make USE_PGXS=1
	sudo make USE_PGXS=1 install

in postgresql execute:

	CREATE EXTENSION uri;

You need to install [liburi](https://github.com/nevali/liburi) to be able to compile the uri
extension. liburi is a simple interface for parsing URIs
based on [uriparser](http://uriparser.sourceforge.net/).


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
- `uri_localpath_content_type(uri)` returns the content_type of a local url.
- `uri_remotepath_content_type(uri)` returns the content_type of a remote url.
- `uri_path_content_type(uri)` returns the content_type of the url (local/remote is autodetected).
- `uri_localpath_size(uri)` returns the size of a local regular file (not symlink).
- `uri_remotepath_size(uri)` returns the size of a remote url.
- `uri_path_size(uri)` returns the size of a local path (not symlink) or remote url (local/remote is autodetected).

In all functions URIs are normalized as they are parsed.
Normalisation is performed according to section 6.2.2 of
RFC3986, and includes adjusting the case of any scheme,
hostname and percent-encoded characters so as to be
consistent, as well as removing redundant components from
the path (for example, a path of /a/b/c/../d/../../e will
be normalised to /a/e). 


operators
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

	INSERT INTO example VALUES (6, 'ftp://ftp.is.co.za/rfc/rfc1808.txt');
	INSERT INTO example VALUES (7, 'http://www.ietf.org/rfc/rfc2396.txt');
	INSERT INTO example VALUES (8, 'ldap://[2001:db8::7]/c=GB?objectClass?one');
	INSERT INTO example VALUES (9, 'mailto:John.Doe@example.com');
	INSERT INTO example VALUES (10, 'news:comp.infosystems.www.servers.unix');
	INSERT INTO example VALUES (11, 'tel:+1-816-555-1212');
	INSERT INTO example VALUES (12, 'telnet://192.0.2.16:80/');
	INSERT INTO example VALUES (13, 'urn:oasis:names:specification:docbook:dtd:xml:4.1.2');
	INSERT INTO example VALUES (13, 'file:///etc/postgresql/9.4/main/postgresql.conf.dist');


Indexes
-------

It is possible to create btree or hash indexes on uri data type.

	CREATE INDEX test2_index_uri ON example USING btree(url uri_btree_ops);
	CREATE INDEX test1_index_uri ON example USING hash(url uri_hash_ops);


Authors
-------

Gilles Darold
gilles@darold.net

License
-------

This extension is free software distributed under the PostgreSQL Licence.

	Copyright (c) 2015-2018, Gilles Darold


