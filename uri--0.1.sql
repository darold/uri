CREATE TYPE uri;
CREATE FUNCTION uri_in(cstring) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_out(uri) RETURNS cstring AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_recv(internal) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_send(uri) RETURNS bytea AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE uri (
        INPUT = uri_in,
        OUTPUT = uri_out,
        INTERNALLENGTH = -1,
        RECEIVE = uri_recv,
        SEND = uri_send,
        STORAGE = extended
);

CREATE CAST (uri AS text) WITH INOUT AS ASSIGNMENT;
CREATE CAST (text AS uri) WITH INOUT AS ASSIGNMENT;

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
CREATE FUNCTION uri_localpath_exists(uri) RETURNS bool AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_localpath_size(uri) RETURNS bigint AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION uri_rebase(uri, uri) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;

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
	NEGATOR = <>,
	HASHES,
	MERGES
);

CREATE OPERATOR <> (
	leftarg = uri,
	rightarg = uri,
	procedure = uri_is_notequal,
	RESTRICT = neqsel,
	RESTRICT = neqsel,
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

