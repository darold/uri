-- uri extension for PostgreSQL
-- Author: Gilles Darold (gilles@darold.net)
-- Copyright (c) 2015-2020 Gilles Darold - All rights reserved.

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION uri" to load this file. \quit

CREATE TYPE uri;
CREATE FUNCTION uri_in(cstring) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_out(uri) RETURNS cstring AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
-- CREATE FUNCTION uri_recv(internal) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
-- CREATE FUNCTION uri_send(uri) RETURNS bytea AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE uri (
        INPUT = uri_in,
        OUTPUT = uri_out,
        INTERNALLENGTH = -1,
--        RECEIVE = uri_recv,
--        SEND = uri_send,
        STORAGE = extended
);

CREATE CAST (uri AS text) WITH INOUT AS IMPLICIT;
CREATE CAST (text AS uri) WITH INOUT AS IMPLICIT;
CREATE CAST (uri AS varchar) WITH INOUT AS IMPLICIT;
CREATE CAST (varchar AS uri) WITH INOUT AS IMPLICIT;

-- URI manipulation function
CREATE FUNCTION uri_get_scheme(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_host(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_auth(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_port(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_portnum(uri) RETURNS integer AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_path(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_query(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_fragment(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_is_absolute(uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_is_absolute_path(uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_get_str(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_localpath_exists(uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_remotepath_exists(uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_localpath_size(uri) RETURNS bigint AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_remotepath_size(uri) RETURNS bigint AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_remotepath_content_type(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_localpath_content_type(uri) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_rebase_url(uri, uri) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_escape(text) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_unescape(text) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION uri_get_relative_path(uri, uri) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_remotepath_header(uri, text) RETURNS text AS 'MODULE_PATHNAME' LANGUAGE C STRICT;

CREATE FUNCTION uri_remotepath_header(uri) RETURNS text AS $$
    SELECT uri_remotepath_header($1, 'text');
$$ LANGUAGE SQL;

CREATE FUNCTION uri_path_exists(uri) RETURNS bool AS $$
DECLARE
	scheme  text;
	path_exists boolean;
BEGIN

	SELECT uri_get_scheme($1) INTO scheme;

	IF scheme = '' OR scheme = 'file' THEN
		SELECT uri_localpath_exists($1) INTO path_exists;
        ELSE
		SELECT uri_remotepath_exists($1) INTO path_exists;
	END IF;

	RETURN path_exists;
END
$$
LANGUAGE plpgsql STRICT;

CREATE FUNCTION uri_path_size(uri) RETURNS bigint AS $$
DECLARE
	scheme  text;
	filesize bigint;
BEGIN

	SELECT uri_get_scheme($1) INTO scheme;

	IF scheme = '' OR scheme = 'file' THEN
		SELECT uri_localpath_size($1) INTO filesize;
        ELSE
		SELECT uri_remotepath_size($1) INTO filesize;
	END IF;

	RETURN filesize;
END
$$
LANGUAGE plpgsql STRICT;

CREATE FUNCTION uri_path_content_type(uri) RETURNS text AS $$
DECLARE
	scheme  text;
	ctype   text;
BEGIN

	SELECT uri_get_scheme($1) INTO scheme;

	IF scheme = '' OR scheme = 'file' THEN
		SELECT uri_localpath_content_type($1) INTO ctype;
        ELSE
		SELECT uri_remotepath_content_type($1) INTO ctype;
	END IF;

	RETURN ctype;
END
$$
LANGUAGE plpgsql STRICT;

-- Indexes related functions
CREATE FUNCTION uri_hash(uri) RETURNS integer AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_compare(uri, uri) RETURNS integer AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_is_equal(uri, uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_is_notequal(uri, uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_contains(uri, uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_contained(uri, uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR = (
	leftarg = uri,
	rightarg = uri,
	procedure = uri_is_equal,
	RESTRICT = eqsel,
	JOIN = eqjoinsel,
	COMMUTATOR = =,
	NEGATOR = <>,
	HASHES,
	MERGES
);

CREATE OPERATOR <> (
	leftarg = uri,
	rightarg = uri,
	procedure = uri_is_notequal,
	RESTRICT = neqsel,
	JOIN = neqjoinsel,
	COMMUTATOR = <>,
	NEGATOR = =
);

CREATE FUNCTION uri_lt(uri, uri) RETURNS BOOL AS $$
    SELECT uri_compare($1, $2) < 0;
$$ LANGUAGE SQL;

CREATE FUNCTION uri_lte(uri, uri) RETURNS BOOL AS $$
    SELECT uri_compare($1, $2) <= 0;
$$ LANGUAGE SQL;

CREATE FUNCTION uri_gt(uri, uri) RETURNS BOOL AS $$
    SELECT uri_compare($1, $2) > 0;
$$ LANGUAGE SQL;

CREATE FUNCTION uri_gte(uri, uri) RETURNS BOOL AS $$
    SELECT uri_compare($1, $2) >= 0;
$$ LANGUAGE SQL;

CREATE OPERATOR < (
	PROCEDURE = uri_lt,
	LEFTARG = uri,
	RIGHTARG = uri,
	COMMUTATOR = >,
	NEGATOR = >=,
	RESTRICT = scalarltsel,
	JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
	PROCEDURE = uri_lte,
	LEFTARG = uri,
	RIGHTARG = uri,
	COMMUTATOR = >=,
	NEGATOR = >,
	RESTRICT = scalarltsel,
	JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
	PROCEDURE = uri_gt,
	LEFTARG = uri,
	RIGHTARG = uri,
	COMMUTATOR = <,
	NEGATOR = <=,
	RESTRICT = scalargtsel,
	JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
	PROCEDURE = uri_gte,
	LEFTARG = uri,
	RIGHTARG = uri,
	COMMUTATOR = <=,
	NEGATOR = <,
	RESTRICT = scalargtsel,
	JOIN = scalargtjoinsel
);

-- hash index support
CREATE OPERATOR CLASS uri_hash_ops
	DEFAULT FOR TYPE uri USING hash AS
	OPERATOR 1 = (uri, uri),
	FUNCTION 1 uri_hash(uri);

-- b-tree index support
CREATE OPERATOR CLASS uri_btree_ops
    DEFAULT FOR TYPE uri USING btree AS
        OPERATOR 1 < (uri, uri),
        OPERATOR 2 <= (uri, uri),
        OPERATOR 3 = (uri, uri),
        OPERATOR 4 >= (uri, uri),
        OPERATOR 5 > (uri, uri),
        FUNCTION 1 uri_compare(uri, uri);

-- Does the left URI value contain within it the right value?
CREATE OPERATOR @> (
    PROCEDURE = uri_contains,
    LEFTARG = uri,
    RIGHTARG = uri,
    COMMUTATOR = <@,
    RESTRICT = contsel,
    JOIN = contjoinsel
);

-- Is the left JSON value contained within the right value?
CREATE OPERATOR <@ (
    PROCEDURE = uri_contained,
    LEFTARG = uri,
    RIGHTARG = uri,
    COMMUTATOR = @>,
    RESTRICT = contsel,
    JOIN = contjoinsel
);

