CREATE EXTENSION uri;

CREATE TABLE t1 (id serial, url uri);
INSERT INTO t1 (url) VALUES ('http://pgcluu.darold.net/index.html');
INSERT INTO t1 (url) VALUES ('file:///opt/git/uri/README');
INSERT INTO t1 (url) VALUES ('http://mydomain.com/pub/../public/../index 1.html');
INSERT INTO t1 (url) VALUES ('http://username:passwd@mydomain.com/pub/index.php');
INSERT INTO t1 (url) VALUES ('http://192.168.1.1/');
INSERT INTO t1 (url) VALUES ('http://pgcluu.darold.net/example/pgbouncer-dolibarr.html#pgbouncer-duration');
INSERT INTO t1 (url) VALUES ('ftp://ftp.is.co.za/rfc/rfc1808.txt');
INSERT INTO t1 (url) VALUES ('http://www.ietf.org/rfc/rfc2396.txt');
INSERT INTO t1 (url) VALUES ('ldap://[2001:db8::7]/c=GB?objectClass?one');
--INSERT INTO t1 (url) VALUES ('mailto:John.Doe@test.com');
--INSERT INTO t1 (url) VALUES ('news:comp.infosystems.www.servers.unix');
--INSERT INTO t1 (url) VALUES ('tel:+1-816-555-1212');
INSERT INTO t1 (url) VALUES ('telnet://192.0.2.16:80/');
--INSERT INTO t1 (url) VALUES ('urn:oasis:names:specification:docbook:dtd:xml:4.1.2');
INSERT INTO t1 (url) VALUES ('switch?toggle=1');
INSERT INTO t1 (url) VALUES ('file:///etc/postgresql/11/main/postgresql.conf');
INSERT INTO t1 (url) VALUES ('file:///etc/postgresql/11/main/../../11/main/pg_hba.conf');
INSERT INTO t1 (url) VALUES ('/etc/postgresql/9.6/main/postgresql.conf');
-- Normalize URIs according to RFC 3986
INSERT INTO t1 (url) VALUES ('HTTPS://www.Example.com:443/../test/../foo/index.html');
INSERT INTO t1 (url) VALUES ('https://WWW.EXAMPLE.COM/./foo/index.html');
INSERT INTO t1 (url) VALUES ('https://www.example.com/%66%6f%6f/index.html');
INSERT INTO t1 (url) VALUES ('https://www.example.com/foo/index.html');

-- Test index creation
CREATE INDEX t1_btree_index_uri ON t1 USING btree(url);
ANALYZE t1;

-- Get all records
SELECT * FROM t1;

-- Use btree index
SET enable_seqscan = off;
EXPLAIN (COSTS off) SELECT * FROM t1 WHERE url = 'file:///etc/postgresql/11/main/../../11/main/pg_hba.conf';
SET enable_seqscan = on;

-- Test all functions of the uri extension
\x on
SELECT url as uri,
        uri_get_scheme(url) as scheme,
        uri_get_auth(url) as authen,
        uri_get_host(url) as host,
        uri_get_port(url) as port,
        uri_get_portnum(url) as port,
        uri_get_path(url) as path,
        uri_get_query(url) as query,
        uri_get_fragment(url) as fragment
  FROM t1;

-- Test all extended functions
SELECT
	uri_get_str('http://192.168.1.1/index.html') as string,
	uri_is_absolute('http://192.168.1.1/index.html') as abs_true,
	uri_is_absolute('/index.html') as abs_false,
	uri_is_absolute_path('/index.html') as abs_path_true,
	uri_is_absolute_path('index.html') as abs_path_false,
	uri_localpath_exists('/etc/fstab') as local_exists_true,
	uri_localpath_exists('/etc/fstab.no') as local_exists_false,
	uri_remotepath_exists('http://ora2pg.darold.net/index.html') as remotepath_true,
	uri_remotepath_exists('http://ora2pg.darold.net/index2.html') as remotepath_false,
	uri_path_exists('http://ora2pg.darold.net/index.html') as rpath_exists_true,
	uri_path_exists('http://ora2pg.darold.net/index2.html') as rpath_exists_false,
	uri_path_exists('/etc/fstab') as lpath_exists_true,
	uri_path_exists('/etc/motd') as lpath_exists_false, -- Symlink
	uri_localpath_content_type('/etc/fstab') as local_content_type,
	uri_remotepath_content_type('http://ora2pg.darold.net/index.html') as remote_content_type,
	uri_path_content_type('/etc/fstab') as lpath_content_type,
	uri_path_content_type('https://avatars2.githubusercontent.com/u/538862?s=40&v=4') as rpath_content_type,
	uri_localpath_size('/etc/fstab') as local_size,
	uri_remotepath_size('http://ora2pg.darold.net/index.html') as remote_size,
	uri_path_size('/etc/fstab') as lpath_size,
	uri_path_size('http://www.darold.net/confs/pgday_2017_partitionnement.pdf') as rpath_size;
\x off

-- Test sorting
SELECT DISTINCT url FROM t1 ORDER BY url;
-- Test sort using index only scan
SET enable_seqscan = off;
EXPLAIN (COSTS off) SELECT DISTINCT url FROM t1 ORDER BY url;
SET enable_seqscan = on;

-- Test hash join
CREATE TABLE t2 (lbl text, url uri);
INSERT INTO t2 VALUES ('mybox', 'http://192.168.1.1/');
ANALYZE t2;
SET enable_nestloop = off;
SET enable_mergejoin = off;
SELECT * FROM t1 JOIN t2 ON t1.url = t2.url AND t1.id = 5;
EXPLAIN (COSTS off) SELECT * FROM t1 JOIN t2 ON t1.url = t2.url AND t1.id = 5;
SET enable_nestloop = on;
SET enable_mergejoin = on;

-- Test hash index
DROP INDEX t1_btree_index_uri;
CREATE INDEX t1_hash_index_uri  ON t1 USING hash(url);
ANALYZE t1;
SET enable_seqscan = off;
SET enable_hashjoin = off;
SET enable_mergejoin = off;
SELECT * FROM t1 JOIN t2 ON t1.url = t2.url AND t1.id = 5;
EXPLAIN (COSTS off) SELECT * FROM t1 JOIN t2 ON t1.url = t2.url AND t1.id = 5;
SET enable_seqscan = on;
SET enable_hashjoin = on;
SET enable_mergejoin = on;

-- Test contain operators
SELECT * FROM t1 WHERE url @> '192.168.1.1';
SELECT * FROM t1 WHERE '192.168.1.1' <@ url;
SELECT * FROM t1 WHERE 'http://192.168.1.1/index.html' @> url;
SELECT * FROM t1 WHERE url <@ 'http://192.168.1.1/index.html';

-- Test URL encoding
SELECT uri_escape('$ & < > ? ; # : = , " '' ~ + % \r \n');
SELECT uri_unescape('%24%20%26%20%3C%20%3E%20%3F%20%3B%20%23%20%3A%20%3D%20%2C%20%22%20%27%20~%20%2B%20%25%20%5Cr%20%5Cn');
SELECT uri_escape(E'Test\nnew line');
SELECT uri_unescape('Test%0Anew%20line');

-- Rebase a path from a base URI, returns http://localhost/tmp/test_dir/dir1/index.html
SELECT uri_rebase_url('dir1/index.html', 'http://localhost/tmp/test_dir/');
-- A base always end with a / any extra path after last / is removed from the base
SELECT uri_rebase_url('dir1/index.html', 'http://localhost/tmp/test_dir');
-- A base must be an URL, if it's an absolute path a file:// is appened internaly
-- Must return: file:///tmp/test_dir/dir1/index.html
SELECT uri_rebase_url('dir1/index.html', '/tmp/test_dir/');

-- Relative path, all three queries must return:  dir1/file.txt
SELECT uri_get_relative_path('file:///tmp/test_dir/dir1/file.txt', 'file:///tmp/test_dir');
SELECT uri_get_relative_path('/tmp/test_dir/dir1/file.txt', '/tmp/test_dir');
SELECT uri_get_relative_path('/tmp/test_dir/dir1/file.txt', 'file:///tmp/test_dir');
