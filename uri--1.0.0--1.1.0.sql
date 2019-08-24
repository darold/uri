ALTER FUNCTION uri_rebase(uri, uri) RENAME TO uri_rebase_url(uri, uri);

CREATE FUNCTION uri_get_relative_path(uri, uri) RETURNS uri AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
