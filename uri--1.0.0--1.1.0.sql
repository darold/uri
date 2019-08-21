ALTER FUNCTION uri_rebase(uri, uri) RENAME TO uri_rebase_url(uri, uri);

-- Function uri_get_relative_path() can be used to return the path
-- of a URI relative to its base specified as second parameter.
CREATE FUNCTION uri_get_relative_path(uri, uri) RETURNS text AS $$
DECLARE
	v_uri uri;
	v_path text;
	v_base text;
BEGIN
	-- Rebase the URL/path with the speficied base
	SELECT uri_rebase_url($1, $2) INTO v_uri;
	SELECT uri_get_path(v_uri) INTO v_path;
	SELECT uri_get_path($2) INTO v_base;
	-- Add a / at end of the base if this is not already the case
	IF regexp_match(v_base, '/$') IS NULL THEN
		v_base := v_base||'/';
	END IF;
	-- Remove the base from the path
	SELECT regexp_replace(v_path, '^'||v_base, '') INTO v_path;
	RETURN v_path;
END
$$ LANGUAGE plpgsql STRICT;

