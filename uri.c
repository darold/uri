/*
 * Uri is an extention to store wellformed URI and retrieve URL informations
 * Author: Gilles Darold (gilles@darold.net)
 * Copyright (c) 2015-2026 Gilles Darold - All rights reserved.
 */

/*
 * uri is an extension to add uri data type for postgresql,
 * it allows to insert data in uri format and provide all
 * functions to extract uri parts and compare uris.
 * It has the following operators =, <>, <, <=, >, >=, @>
 * and <@.
 */

/*
 * URI parsing is delegated to uriparser (https://uriparser.github.io/).
 * Earlier releases embedded wrapper code derived from liburi
 * (https://github.com/bbcarchdev/liburi); that code has been removed and
 * replaced by direct calls to the uriparser API.
 */
#include "postgres.h"
#include "access/hash.h"
#include "common/fe_memutils.h"
#include "catalog/pg_type.h"
#include "fmgr.h"
#include "libpq/pqformat.h"
#include "utils/builtins.h"
#if PG_VERSION_NUM >= 130000
#include "common/jsonapi.h"
#include "utils/jsonfuncs.h"
#else
#include "utils/jsonapi.h"
#endif
#include "utils/varlena.h"

#include <stdio.h>
#include <string.h>
#include <uriparser/Uri.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <magic.h>

#define MAXREDIR     3
#define CURL_TIMEOUT 6

#define TRUE         1
#define FALSE        0

typedef struct varlena t_uri;

/* Storage for curl header fetch */
struct curl_fetch_st {
	char *data;
	size_t size;
};

/* the null action object used for pure json validation */
/*
static JsonSemAction nullSemAction =
{
	NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
};
*/

/* Forward declarations of non-PG helpers */
char *get_filetype(char *filename);
bool is_real_file(char *filename);
char *uriToStr(const char *url);
bool _isspace(char ch);
bool SplitHeaderLine(char *rawstring, List **namelist);
bool SplitHeaderField(char *rawstring, List **namelist);

/*
 * --------------------------------------------------------------------------
 *  uriparser helpers
 * --------------------------------------------------------------------------
 *
 *  These small helpers wrap the uriparser API in a way that matches the
 *  needs of this extension. They replace the liburi-derived wrapper layer
 *  that previously lived in this file.
 *
 *  The PostgreSQL entry points below all follow the same pattern:
 *
 *      UriUriA uri;
 *
 *      if (!uri_parse(url, &uri))
 *              ereport(ERROR, ...);
 *      ... read parts via the helpers below ...
 *      uriFreeUriMembersA(&uri);
 *
 *  No heap allocation is required for the parser state itself.
 */

/*
 * Map an IRI to a URI: percent-encode every input byte that falls outside
 * the printable ASCII range, leaving printable ASCII (including reserved
 * characters with URI semantics) untouched. UTF-8 multi-byte sequences are
 * encoded byte-by-byte, which yields a valid percent-encoded URI.
 *
 * Returns a freshly palloc'd buffer; *changed is set when any byte was
 * actually escaped.
 */
static char *
uri_escape_non_ascii(const char *src, bool *changed)
{
	static const char hex[] = "0123456789ABCDEF";
	StringInfoData buf;
	const unsigned char *p;

	initStringInfo(&buf);
	*changed = false;

	for (p = (const unsigned char *) src; *p; p++)
	{
		if (*p < 33 || *p > 126)
		{
			appendStringInfoChar(&buf, '%');
			appendStringInfoChar(&buf, hex[*p >> 4]);
			appendStringInfoChar(&buf, hex[*p & 0x0f]);
			*changed = true;
		}
		else
			appendStringInfoChar(&buf, (char) *p);
	}
	return buf.data;
}

/*
 * Returns true if the URI is non-hierarchical (scheme is followed by
 * something other than '/' or '\'). The previous implementation rejected
 * such URIs explicitly; we preserve that contract.
 */
static bool
uri_is_non_hierarchical(const char *url)
{
	const char *p;

	for (p = url; p && *p; p++)
	{
		if (*p == ':')
			return (p[1] != '/' && p[1] != '\\' && p[1] != '\0');
		if (*p == '@' || *p == '/' || *p == '%' || *p == '\\')
			return false;
	}
	return false;
}

/*
 * Parse and normalise a URI string. On success the caller is responsible
 * for releasing the parser-owned memory with uriFreeUriMembersA().
 *
 * The input is preprocessed to percent-encode any byte outside printable
 * ASCII, so that IRI-like inputs (e.g. URLs containing spaces or UTF-8)
 * are accepted just as they were by the previous liburi-based wrapper.
 *
 * Non-hierarchical URIs (e.g. "mailto:", "urn:") are rejected with the
 * dedicated error used historically.
 */
static bool
uri_parse(const char *url, UriUriA *uri)
{
	char *escaped;
	bool  changed;
	int   rc;

	if (uri_is_non_hierarchical(url))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("non-hierarchical URI are not supported: \"%s\"", url)));

	escaped = uri_escape_non_ascii(url, &changed);
	rc = uriParseSingleUriA(uri, escaped, NULL);

	if (rc != URI_SUCCESS)
	{
		pfree(escaped);
		return false;
	}

	/*
	 * The parser leaves text ranges pointing into the input buffer; detach
	 * them so the UriUriA remains valid after we free our escaped copy.
	 */
	if (uriMakeOwnerA(uri) != URI_SUCCESS)
	{
		uriFreeUriMembersA(uri);
		pfree(escaped);
		return false;
	}
	pfree(escaped);

	uriNormalizeSyntaxA(uri);
	return true;
}

/*
 * Copy a UriTextRangeA into a freshly malloc'd, NUL-terminated string.
 * Returns NULL if the range is empty.
 */
static char *
uri_range_dup(const UriTextRangeA *range)
{
	size_t  len;
	char   *out;

	if (!range || !range->first || !range->afterLast
		|| range->afterLast == range->first)
		return NULL;

	len = range->afterLast - range->first;
	out = (char *) malloc(len + 1);
	if (!out)
		return NULL;

	memcpy(out, range->first, len);
	out[len] = '\0';
	return out;
}

/*
 * Serialise a UriUriA into a freshly malloc'd C string.
 */
static char *
uri_to_string(const UriUriA *uri)
{
	int   needed;
	char *buf;

	if (uriToStringCharsRequiredA(uri, &needed) != URI_SUCCESS)
		return NULL;
	needed++;

	buf = (char *) malloc(needed);
	if (!buf)
		return NULL;

	if (uriToStringA(buf, uri, needed, NULL) != URI_SUCCESS)
	{
		free(buf);
		return NULL;
	}
	return buf;
}

/*
 * Reconstruct the path component as a freshly malloc'd C string.
 * Returns NULL when the URI carries no path.
 */
static char *
uri_path_dup(const UriUriA *uri)
{
	StringInfoData str;
	UriPathSegmentA *p;
	bool absolute;
	char *out;

	if (!uri->pathHead && uri->absolutePath != URI_TRUE && !uri->hostText.first)
		return NULL;

	/*
	 * A URI path is rendered with a leading slash when the URI itself
	 * is absolute, when the parser flagged the path as absolute, or
	 * when the URI has an authority component (host).
	 */
	absolute = (uri->absolutePath == URI_TRUE) || (uri->hostText.first != NULL);

	initStringInfo(&str);
	if (absolute)
		appendStringInfoChar(&str, '/');

	for (p = uri->pathHead; p; p = p->next)
	{
		if (p != uri->pathHead)
			appendStringInfoChar(&str, '/');
		if (p->text.first && p->text.afterLast > p->text.first)
			appendBinaryStringInfo(&str, p->text.first,
								   p->text.afterLast - p->text.first);
	}

	/* Move to malloc'd storage so callers can free() the result. */
	out = strdup(str.data);
	pfree(str.data);
	return out;
}

/*
 * Declaration of the URI data type function
 */

PG_MODULE_MAGIC;
Datum		uri_in(PG_FUNCTION_ARGS);
Datum		uri_out(PG_FUNCTION_ARGS);
/*
Datum		uri_recv(PG_FUNCTION_ARGS);
Datum		uri_send(PG_FUNCTION_ARGS);
*/
Datum		uri_is_equal(PG_FUNCTION_ARGS);
Datum		uri_is_notequal(PG_FUNCTION_ARGS);
Datum		uri_hash(PG_FUNCTION_ARGS);
Datum		uri_get_scheme(PG_FUNCTION_ARGS);
Datum		uri_get_host(PG_FUNCTION_ARGS);
Datum		uri_get_auth(PG_FUNCTION_ARGS);
Datum		uri_get_port(PG_FUNCTION_ARGS);
Datum		uri_get_path(PG_FUNCTION_ARGS);
Datum		uri_get_query(PG_FUNCTION_ARGS);
Datum		uri_get_fragment(PG_FUNCTION_ARGS);
Datum		uri_compare(PG_FUNCTION_ARGS);
Datum		uri_localfile_exists(PG_FUNCTION_ARGS);
Datum		uri_contains(PG_FUNCTION_ARGS);
Datum		uri_contained(PG_FUNCTION_ARGS);
Datum		uri_rebase_url(PG_FUNCTION_ARGS);
Datum		uri_localpath_exists(PG_FUNCTION_ARGS);
Datum		uri_localpath_size(PG_FUNCTION_ARGS);
Datum		uri_remotepath_exists(PG_FUNCTION_ARGS);
Datum		uri_remotepath_size(PG_FUNCTION_ARGS);
Datum		uri_remotepath_content_type(PG_FUNCTION_ARGS);
Datum		uri_localpath_content_type(PG_FUNCTION_ARGS);
Datum		uri_escape(PG_FUNCTION_ARGS);
Datum		uri_unescape(PG_FUNCTION_ARGS);
Datum		uri_get_relative_path(PG_FUNCTION_ARGS);

/*
 * Parse the URL, normalise it and return its canonical string form.
 * Caller must free() the result.
 */
char *
uriToStr(const char *url)
{
	UriUriA uri;
	char   *buffer;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	buffer = uri_to_string(&uri);
	uriFreeUriMembersA(&uri);

	if (!buffer)
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get string from URI: \"%s\"", url)));

	return buffer;
}


PG_FUNCTION_INFO_V1(uri_in);
Datum
uri_in(PG_FUNCTION_ARGS)
{
	const char	*url = PG_GETARG_CSTRING(0);

	PG_RETURN_POINTER((t_uri *) cstring_to_text(uriToStr(url)));
}

PG_FUNCTION_INFO_V1(uri_out);
Datum
uri_out(PG_FUNCTION_ARGS)
{
	char	*url = TextDatumGetCString(PG_GETARG_DATUM(0));

	PG_RETURN_CSTRING(url);
}

PG_FUNCTION_INFO_V1(uri_get_scheme);
Datum
uri_get_scheme(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *scheme;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	scheme = uri_range_dup(&uri.scheme);
	uriFreeUriMembersA(&uri);

	if (!scheme)
		PG_RETURN_TEXT_P(cstring_to_text(""));

	PG_RETURN_TEXT_P(cstring_to_text(scheme));
}

PG_FUNCTION_INFO_V1(uri_get_auth);
Datum
uri_get_auth(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *auth;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	auth = uri_range_dup(&uri.userInfo);
	uriFreeUriMembersA(&uri);

	if (!auth)
		PG_RETURN_NULL();

	PG_RETURN_TEXT_P(cstring_to_text(auth));
}

PG_FUNCTION_INFO_V1(uri_get_host);
Datum
uri_get_host(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *host;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	host = uri_range_dup(&uri.hostText);
	uriFreeUriMembersA(&uri);

	if (!host)
		PG_RETURN_NULL();

	PG_RETURN_TEXT_P(cstring_to_text(host));
}

PG_FUNCTION_INFO_V1(uri_get_port);
Datum
uri_get_port(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *port;
	text    *result;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	port = uri_range_dup(&uri.portText);
	uriFreeUriMembersA(&uri);

	result = cstring_to_text(port ? port : "");
	PG_RETURN_TEXT_P(result);
}

PG_FUNCTION_INFO_V1(uri_get_portnum);
Datum
uri_get_portnum(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *port;
	int      portnum = 0;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	port = uri_range_dup(&uri.portText);
	uriFreeUriMembersA(&uri);

	if (port)
	{
		portnum = atoi(port);
		if (portnum < 1 || portnum > 65535)
			portnum = 0;
		free(port);
	}

	PG_RETURN_INT16(portnum);
}

PG_FUNCTION_INFO_V1(uri_get_path);
Datum
uri_get_path(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *path;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	path = uri_path_dup(&uri);
	uriFreeUriMembersA(&uri);

	if (!path || path[0] == '\0')
	{
		if (path)
			free(path);
		PG_RETURN_NULL();
	}

	PG_RETURN_TEXT_P(cstring_to_text(path));
}

PG_FUNCTION_INFO_V1(uri_get_query);
Datum
uri_get_query(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *query;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	query = uri_range_dup(&uri.query);
	uriFreeUriMembersA(&uri);

	if (!query)
		PG_RETURN_NULL();

	PG_RETURN_TEXT_P(cstring_to_text(query));
}

PG_FUNCTION_INFO_V1(uri_get_fragment);
Datum
uri_get_fragment(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *fragment;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	fragment = uri_range_dup(&uri.fragment);
	uriFreeUriMembersA(&uri);

	if (!fragment)
		PG_RETURN_NULL();

	PG_RETURN_TEXT_P(cstring_to_text(fragment));
}

PG_FUNCTION_INFO_V1(uri_is_absolute);
Datum
uri_is_absolute(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	bool     absolute;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	absolute = (uri.scheme.first != NULL);
	uriFreeUriMembersA(&uri);

	PG_RETURN_BOOL(absolute);
}

PG_FUNCTION_INFO_V1(uri_is_absolute_path);
Datum
uri_is_absolute_path(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	bool     absolute;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	absolute = (uri.absolutePath == URI_TRUE) || (uri.hostText.first != NULL);
	uriFreeUriMembersA(&uri);

	PG_RETURN_BOOL(absolute);
}

PG_FUNCTION_INFO_V1(uri_get_str);
Datum
uri_get_str(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));

	PG_RETURN_TEXT_P(cstring_to_text(uriToStr(url)));
}

PG_FUNCTION_INFO_V1(uri_is_equal);
Datum
uri_is_equal(PG_FUNCTION_ARGS)
{
	char    *url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char    *url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
	UriUriA  uri1, uri2;
	bool     equal;

	if (!uri_parse(url1, &uri1))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url1)));

	if (!uri_parse(url2, &uri2))
	{
		uriFreeUriMembersA(&uri1);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url2)));
	}

	equal = (uriEqualsUriA(&uri1, &uri2) == URI_TRUE);
	uriFreeUriMembersA(&uri1);
	uriFreeUriMembersA(&uri2);

	PG_RETURN_BOOL(equal);
}

PG_FUNCTION_INFO_V1(uri_is_notequal);
Datum
uri_is_notequal(PG_FUNCTION_ARGS)
{
	char    *url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char    *url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
	UriUriA  uri1, uri2;
	bool     equal;

	if (!uri_parse(url1, &uri1))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url1)));

	if (!uri_parse(url2, &uri2))
	{
		uriFreeUriMembersA(&uri1);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url2)));
	}

	equal = (uriEqualsUriA(&uri1, &uri2) == URI_TRUE);
	uriFreeUriMembersA(&uri1);
	uriFreeUriMembersA(&uri2);

	PG_RETURN_BOOL(!equal);
}

PG_FUNCTION_INFO_V1(uri_hash);
Datum
uri_hash(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));

	PG_RETURN_INT32(DatumGetInt32(hash_any((unsigned char *) url, strlen(url))));
}

PG_FUNCTION_INFO_V1(uri_compare);
Datum
uri_compare(PG_FUNCTION_ARGS)
{
	char    *url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char    *url2 = TextDatumGetCString(PG_GETARG_DATUM(1));

	PG_RETURN_INT32(strcmp(uriToStr(url1), uriToStr(url2)));
}

bool
is_real_file(char *filename)
{
	bool		exists = true;
	struct stat	statbuf;
	char          *dstpath;

	/*
	 * Does the corresponding local file exists as a regular file?
	 * Get the real path of the file when it is a symlink.
	 */
	dstpath = realpath(filename, NULL);
	if (dstpath == NULL)
	{
		if (errno != ENOENT)
		{
			int save_errno = errno;
			ereport(ERROR, (
				errmsg("could not get real path of file \"%s\": %s",
						filename, strerror(save_errno))));
		}
		exists = false;
	}
	else
	{
		if (stat(dstpath, &statbuf) < 0)
		{
			free(dstpath);
			if (errno != ENOENT)
			{
				int save_errno = errno;
				ereport(ERROR, (
					errmsg("could not stat file \"%s\": %s",
							filename, strerror(save_errno))));
			}
			exists = false;
		}
		free(dstpath);
	}

	return exists;
}

PG_FUNCTION_INFO_V1(uri_localpath_exists);
Datum
uri_localpath_exists(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *path;
	bool     exists;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	path = uri_path_dup(&uri);
	uriFreeUriMembersA(&uri);

	exists = path ? is_real_file(path) : false;
	if (path)
		free(path);

	PG_RETURN_BOOL(exists);
}

PG_FUNCTION_INFO_V1(uri_contains);
Datum
uri_contains(PG_FUNCTION_ARGS)
{
	char    *url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char    *url2 = TextDatumGetCString(PG_GETARG_DATUM(1));

	if (strcasestr(uriToStr(url1), uriToStr(url2)) != NULL)
		PG_RETURN_BOOL(true);

	PG_RETURN_BOOL(false);
}

PG_FUNCTION_INFO_V1(uri_contained);
Datum
uri_contained(PG_FUNCTION_ARGS)
{
	PG_RETURN_DATUM(DirectFunctionCall2( uri_contains, PG_GETARG_DATUM(1), PG_GETARG_DATUM(0) ));
}

PG_FUNCTION_INFO_V1(uri_rebase_url);
Datum
uri_rebase_url(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char    *base = TextDatumGetCString(PG_GETARG_DATUM(1));
	UriUriA  b_uri, h_uri, abs_uri;
	char    *buffer;

	/*
	 * When base is a path only, prepend file:// so that uriparser
	 * recognises it as an absolute URI suitable for rebasing.
	 */
	if (base[0] == '/')
	{
		char *tmp_str = palloc0(sizeof(char)*(strlen(base)+8));
		snprintf(tmp_str, strlen(base)+8, "file://%s", base);
		pfree(base);
		base = tmp_str;
	}

	if (!uri_parse(base, &b_uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", base)));

	if (!uri_parse(url, &h_uri))
	{
		uriFreeUriMembersA(&b_uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}

	if (uriAddBaseUriA(&abs_uri, &h_uri, &b_uri) != URI_SUCCESS)
	{
		uriFreeUriMembersA(&b_uri);
		uriFreeUriMembersA(&h_uri);
		PG_RETURN_NULL();
	}

	/*
	 * abs_uri's text ranges initially point into the source URIs' buffers;
	 * detach them so the result remains valid after we free h_uri/b_uri.
	 */
	if (uriMakeOwnerA(&abs_uri) != URI_SUCCESS)
	{
		uriFreeUriMembersA(&abs_uri);
		uriFreeUriMembersA(&b_uri);
		uriFreeUriMembersA(&h_uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to detach rebased URI: \"%s\" on base \"%s\"", url, base)));
	}
	uriFreeUriMembersA(&b_uri);
	uriFreeUriMembersA(&h_uri);

	uriNormalizeSyntaxA(&abs_uri);
	buffer = uri_to_string(&abs_uri);
	uriFreeUriMembersA(&abs_uri);

	if (!buffer)
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get string from rebased URI: \"%s\" on base \"%s\"", url, base)));

	PG_RETURN_POINTER((t_uri *) cstring_to_text(buffer));
}

PG_FUNCTION_INFO_V1(uri_localpath_size);
Datum
uri_localpath_size(PG_FUNCTION_ARGS)
{
	char        *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA      uri;
	char        *path;
	char        *dstpath;
	struct stat  statbuf;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	path = uri_path_dup(&uri);
	uriFreeUriMembersA(&uri);

	if (!path)
		PG_RETURN_NULL();

	/* Does the corresponding local file exists? */
	dstpath = realpath(path, NULL);
	if (dstpath == NULL)
	{
		if (errno != ENOENT)
		{
			int save_errno = errno;
			ereport(ERROR, (
				errmsg("could not get real path of file \"%s\": %s",
						path, strerror(save_errno))));
		}
		free(path);
		PG_RETURN_NULL();
	}
	if (stat(dstpath, &statbuf) < 0)
	{
		free(dstpath);
		if (errno != ENOENT)
		{
			int save_errno = errno;
			ereport(ERROR, (
				errmsg("could not stat file \"%s\": %s",
						path, strerror(save_errno))));
		}
		free(path);
		PG_RETURN_NULL();
	}
	else
	{
		free(dstpath);
		/* check if it is a symlink and return NULL in this case */
		switch(statbuf.st_mode & S_IFMT)
		{
		    case S_IFLNK:
			ereport(WARNING,
				(errmsg("could not get size of a symlink \"%s\", not authorized",
					path)));
			free(path);
			PG_RETURN_NULL();
			break;
		}
	}
	free(path);

	PG_RETURN_INT64(statbuf.st_size);
}

PG_FUNCTION_INFO_V1(uri_remotepath_exists);
Datum
uri_remotepath_exists(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	bool     exists;
	struct curl_slist *slist = NULL;
	CURL *eh = NULL;        /* libcurl handler */
	CURLcode res ;
	char err[CURL_ERROR_SIZE];

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	uriFreeUriMembersA(&uri);

	/* curl init */
	curl_global_init (CURL_GLOBAL_ALL);
	/* get an easy handle */
	if ((eh = curl_easy_init ()) == NULL)
	{
		ereport(FATAL,
			(errmsg("could not instantiate libcurl using curl_easy_init ()")));
	}
	else
	{
          /* set the error buffer */
          curl_easy_setopt (eh, CURLOPT_ERRORBUFFER, err);
          /* do not install signal  handlers in thread context */
          curl_easy_setopt (eh, CURLOPT_NOSIGNAL, 1);
          /* Force HTTP 1.0 version */
          curl_easy_setopt (eh, CURL_HTTP_VERSION_1_0, TRUE);
          /* Do not fail on errors: use to prevent breaked download */
	  curl_easy_setopt (eh, CURLOPT_FAILONERROR, FALSE);
          /* follow location (303 MOVED) */
          curl_easy_setopt (eh, CURLOPT_FOLLOWLOCATION, TRUE);
          /* only follow MAXREDIR redirects */
          curl_easy_setopt (eh, CURLOPT_MAXREDIRS, MAXREDIR);
          /* overwrite the Pragma: no-cache HTTP header */
          slist = curl_slist_append(slist, "pragma:");
          curl_easy_setopt (eh, CURLOPT_HTTPHEADER, slist);
          /* set the url */
          curl_easy_setopt (eh, CURLOPT_URL, url);
          /* set the libcurl transfer timeout to max CURL_TIMEOUT second for header */
          curl_easy_setopt (eh, CURLOPT_TIMEOUT, CURL_TIMEOUT);
          /* Suppress error: SSL certificate problem, verify that the CA cert is OK */
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYHOST, FALSE);
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYPEER, FALSE);
	  /* only get the header to check size and content type */
	  curl_easy_setopt (eh, CURLOPT_NOBODY, TRUE);
	}

	res = curl_easy_perform (eh);
	if (res != CURLE_OK)
	{
		/* can not establish a connection */
		exists = false;
	}
	else
	{
		long http_code = 0;
		res = curl_easy_getinfo(eh, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 404)
		{
			exists = false;
		}
		else
		{
			if (http_code >= 400)
			{
				ereport(WARNING,
					(errmsg("Can not access to remote object \"%s\", HTTP code returned: %lu",
						url, http_code)));
				curl_global_cleanup ();
				PG_RETURN_NULL();
			}
			else
			{
				exists = true;
			}
		}
	}
	curl_global_cleanup ();

	PG_RETURN_BOOL(exists);
}

PG_FUNCTION_INFO_V1(uri_remotepath_size);
Datum
uri_remotepath_size(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	struct curl_slist *slist = NULL;
	CURL *eh = NULL;        /* libcurl handler */
	CURLcode res ;
	char err[CURL_ERROR_SIZE];
	curl_off_t filesize;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	uriFreeUriMembersA(&uri);

	/* curl init */
	curl_global_init (CURL_GLOBAL_ALL);
	/* get an easy handle */
	if ((eh = curl_easy_init ()) == NULL)
	{
		ereport(FATAL,
			(errmsg("could not instantiate libcurl using curl_easy_init ()")));
	}
	else
	{
          curl_easy_setopt (eh, CURLOPT_ERRORBUFFER, err);
          curl_easy_setopt (eh, CURLOPT_NOSIGNAL, 1);
          curl_easy_setopt (eh, CURL_HTTP_VERSION_1_0, TRUE);
	  curl_easy_setopt (eh, CURLOPT_FAILONERROR, FALSE);
          curl_easy_setopt (eh, CURLOPT_FOLLOWLOCATION, TRUE);
          curl_easy_setopt (eh, CURLOPT_MAXREDIRS, MAXREDIR);
          slist = curl_slist_append(slist, "pragma:");
          curl_easy_setopt (eh, CURLOPT_HTTPHEADER, slist);
          curl_easy_setopt (eh, CURLOPT_URL, url);
          curl_easy_setopt (eh, CURLOPT_TIMEOUT, CURL_TIMEOUT);
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYHOST, FALSE);
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYPEER, FALSE);
	  curl_easy_setopt (eh, CURLOPT_NOBODY, TRUE);
	}

	res = curl_easy_perform (eh);
	if (res == CURLE_OK)
	{
		long http_code = 0;
		curl_easy_getinfo(eh, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code >= 400)
		{
			ereport(WARNING,
				(errmsg("Can not get size of remote object \"%s\", HTTP code returned: %lu",
					url, http_code)));
			curl_global_cleanup ();
			PG_RETURN_NULL();
		}
		res = curl_easy_getinfo(eh, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &filesize);
		if ((res != CURLE_OK) || (filesize < 0))
		{
			if (res != CURLE_OK)
				ereport(WARNING,
					(errmsg("Can not get size of remote object \"%s\", reason: %s",
						url, curl_easy_strerror(res))));
			curl_global_cleanup ();
			PG_RETURN_NULL();
		}
	}
	curl_global_cleanup ();

	PG_RETURN_INT32(filesize);
}

PG_FUNCTION_INFO_V1(uri_remotepath_content_type);
Datum
uri_remotepath_content_type(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	struct curl_slist *slist = NULL;
	CURL *eh = NULL;        /* libcurl handler */
	CURLcode res ;
	char err[CURL_ERROR_SIZE];
	char *content_type = NULL;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	uriFreeUriMembersA(&uri);

	/* curl init */
	curl_global_init (CURL_GLOBAL_ALL);
	/* get an easy handle */
	if ((eh = curl_easy_init ()) == NULL)
	{
		ereport(FATAL,
			(errmsg("could not instantiate libcurl using curl_easy_init ()")));
	}
	else
	{
          curl_easy_setopt (eh, CURLOPT_ERRORBUFFER, err);
          curl_easy_setopt (eh, CURLOPT_NOSIGNAL, 1);
          curl_easy_setopt (eh, CURL_HTTP_VERSION_1_0, TRUE);
	  curl_easy_setopt (eh, CURLOPT_FAILONERROR, FALSE);
          curl_easy_setopt (eh, CURLOPT_FOLLOWLOCATION, TRUE);
          curl_easy_setopt (eh, CURLOPT_MAXREDIRS, MAXREDIR);
          slist = curl_slist_append(slist, "pragma:");
          curl_easy_setopt (eh, CURLOPT_HTTPHEADER, slist);
          curl_easy_setopt (eh, CURLOPT_URL, url);
          curl_easy_setopt (eh, CURLOPT_TIMEOUT, CURL_TIMEOUT);
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYHOST, FALSE);
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYPEER, FALSE);
	  curl_easy_setopt (eh, CURLOPT_NOBODY, TRUE);
	}

	res = curl_easy_perform (eh);
	if (res == CURLE_OK)
	{
		long http_code = 0;
		curl_easy_getinfo(eh, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code >= 400)
		{
			ereport(WARNING,
				(errmsg("Can not get content-type of remote object \"%s\", HTTP code returned: %lu",
					url, http_code)));
			curl_global_cleanup ();
			PG_RETURN_NULL();
		}
		res = curl_easy_getinfo(eh, CURLINFO_CONTENT_TYPE, &content_type);
		if ((res != CURLE_OK) || (content_type == NULL))
		{
			if (res != CURLE_OK)
				ereport(WARNING,
					(errmsg("Can not get content-type of remote object \"%s\", reason: %s",
						url, curl_easy_strerror(res))));
			curl_global_cleanup ();
			PG_RETURN_NULL();
		}
	}
	curl_global_cleanup ();

	if (!content_type)
		PG_RETURN_NULL();

	PG_RETURN_TEXT_P(cstring_to_text(content_type));
}

char *
get_filetype(char *filename)
{

	const char *magic_str;
	const char *magic_err;
	magic_t    magic_cookie;
	char *mime;

	/* Initialize magic library */
	magic_cookie = magic_open(MAGIC_MIME);
	if (magic_cookie == NULL)
	{
		ereport(FATAL, (errmsg("unable to initialize magic library")));
	}
	/* Loading default magic database */
	if (magic_load(magic_cookie, NULL) != 0)
	{
		magic_err = magic_error(magic_cookie);
		magic_close(magic_cookie);
		ereport(FATAL,
			(errmsg("cannot load magic database - %s",
				magic_err)));
	}

	magic_str = magic_file(magic_cookie, filename);
	if (magic_errno(magic_cookie) > 0)
	{
		ereport(WARNING,
			(errmsg("cannot look for mime-type of file %s - %s",
				filename, magic_error(magic_cookie))));
		magic_close(magic_cookie);
		return NULL;

	}

	mime = strdup(magic_str);
	if (!mime)
	{
		magic_close(magic_cookie);
		fprintf(stderr, _("out of memory\n"));
		return NULL;
	}

	magic_close(magic_cookie);

	return mime;
}

PG_FUNCTION_INFO_V1(uri_localpath_content_type);
Datum
uri_localpath_content_type(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	UriUriA  uri;
	char    *path;
	char    *mime;

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));

	path = uri_path_dup(&uri);
	uriFreeUriMembersA(&uri);

	if (!path)
		PG_RETURN_NULL();

	if (!is_real_file(path))
	{
		free(path);
		PG_RETURN_NULL();
	}

	mime = get_filetype(path);
	free(path);

	if (!mime)
		PG_RETURN_NULL();

	PG_RETURN_TEXT_P(cstring_to_text(mime));
}

PG_FUNCTION_INFO_V1(uri_escape);
Datum
uri_escape(PG_FUNCTION_ARGS)
{
	char	*url = TextDatumGetCString(PG_GETARG_DATUM(0));
	CURL *eh = NULL;        /* libcurl handler */
	char *escaped;

	/* curl init */
	curl_global_init (CURL_GLOBAL_ALL);
	/* get an easy handle */
	if ((eh = curl_easy_init ()) == NULL)
	{
		ereport(FATAL,
			(errmsg("could not instantiate libcurl using curl_easy_init ()")));
	}
	else
	{
		/* do not install signal  handlers in thread context */
		curl_easy_setopt (eh, CURLOPT_NOSIGNAL, 1);
		escaped = curl_easy_escape(eh, url, 0);
		if (escaped)
		{
			curl_global_cleanup ();
			PG_RETURN_TEXT_P(cstring_to_text(escaped));
		}
	}
	curl_global_cleanup ();

	PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(uri_unescape);
Datum
uri_unescape(PG_FUNCTION_ARGS)
{
	char	*url = TextDatumGetCString(PG_GETARG_DATUM(0));
	CURL *eh = NULL;        /* libcurl handler */
	char *unescaped;

	/* curl init */
	curl_global_init (CURL_GLOBAL_ALL);
	/* get an easy handle */
	if ((eh = curl_easy_init ()) == NULL)
	{
		ereport(FATAL,
			(errmsg("could not instantiate libcurl using curl_easy_init ()")));
	}
	else
	{
		/* do not install signal  handlers in thread context */
		curl_easy_setopt (eh, CURLOPT_NOSIGNAL, 1);
		unescaped = curl_easy_unescape(eh, url, 0, NULL);
		if (unescaped)
		{
			curl_global_cleanup ();
			PG_RETURN_TEXT_P(cstring_to_text(unescaped));
		}
	}
	curl_global_cleanup ();

	PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(uri_get_relative_path);
Datum
uri_get_relative_path(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char    *base = TextDatumGetCString(PG_GETARG_DATUM(1));
	UriUriA  b_uri;
	UriUriA  h_uri;
	UriUriA  p_uri;
	int      rc;
	char    *buffer = NULL;
	char    *found = strcasestr(base, "file:///");
	int      needed;

	/*
	 * With a base starting with file:// and a path only as url
	 * we need to remove the scheme from the base
	 */
	if (url[0] == '/' && found != NULL && (found - base) == 0)
		base += 7;

	if (uriParseSingleUriA(&b_uri, base, NULL) != URI_SUCCESS)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", base)));
	}

	if (uriParseSingleUriA(&h_uri, url, NULL) != URI_SUCCESS)
	{
		uriFreeUriMembersA(&b_uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}

	/* in case we can't extract a relative path we return the URL as is */
	if (uriRemoveBaseUriA(&p_uri, &h_uri, &b_uri, URI_FALSE) != URI_SUCCESS)
	{
		int i = 0;

		uriFreeUriMembersA(&b_uri);
		uriFreeUriMembersA(&h_uri);

		/*
		 * When url and base are pathes uriRemoveBaseUriA() do not works,
		 * try to remove the base directory if it is found in the path.
		 */
		for (i = 0; i < strlen(url); i++)
			if (url[i] != base[i])
				break;
		/*
		 * case when the base directory does not end with a /,
		 * prevent a leading / to resulting path
		 */
		if (i > 0 && url[i] == '/')
			i++;
		url += i;
		PG_RETURN_POINTER((t_uri *) cstring_to_text(url));
	}
	uriFreeUriMembersA(&b_uri);
	uriFreeUriMembersA(&h_uri);

	if ((rc = uriToStringCharsRequiredA(&p_uri, &needed)) != URI_SUCCESS)
		elog(ERROR, "uriToStringCharsRequiredA() failed: error code %d", rc);
	needed++;

	if (!needed)
		PG_RETURN_NULL();

	if ((buffer = (char *) malloc(needed)) == NULL ||
		uriToStringA(buffer, &p_uri, needed, NULL) != URI_SUCCESS)
	{
		uriFreeUriMembersA(&p_uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("fail to translate relative path from uri to string")));
	}
	uriFreeUriMembersA(&p_uri);

	PG_RETURN_POINTER((t_uri *) cstring_to_text(buffer));
}

static size_t
header_callback(char *buffer, size_t size,
                              size_t nitems, void *userdata)
{
	size_t realsize = nitems * size;      /* calculate buffer size */
	/* cast pointer to fetch data */
	struct curl_fetch_st *p = (struct curl_fetch_st *) userdata;

	/* guard against integer overflow and excessively large responses */
	if (realsize > (SIZE_MAX - p->size - 1))
		return 0;

	/* increase size of the storage area */
	p->data = (char *) realloc(p->data, p->size + realsize + 1);
	if (p->data == NULL)
	{
		free(p);
		ereport(FATAL,
			(errmsg("failed to expand buffer in curl_callback()")));
	}
	/* copy new received buffer to our storage area */
	memcpy(&(p->data[p->size]), buffer, realsize);

	/* set new size of the data */
	p->size += realsize;

	/* set null termination */
	p->data[p->size] = 0;

	return realsize;
}

PG_FUNCTION_INFO_V1(uri_remotepath_header);
Datum
uri_remotepath_header(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char    *format = TextDatumGetCString(PG_GETARG_DATUM(1));
	UriUriA  uri;
	struct curl_slist *slist = NULL;
	struct curl_fetch_st curl_fetch;		/* curl fetch struct */
	struct curl_fetch_st *fetch = &curl_fetch;	/* pointer to fetch data */
	CURL *eh = NULL;				/* libcurl handler */
	CURLcode res ;
	char err[CURL_ERROR_SIZE];
	List       *linelist = NULL;
	StringInfoData str;
	ListCell   *lc;

	if (format == NULL)
		format = "text";

	if (pg_strncasecmp(format, "text", 4) != 0 && pg_strncasecmp(format, "json", 4) != 0)
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("unrecognize format '%s', supported format are: 'text' and 'json'", format)));

	if (!uri_parse(url, &uri))
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	uriFreeUriMembersA(&uri);

	/* init callback data */
	fetch->data = (char *) calloc(1, sizeof(char));
	if (fetch->data == NULL) {
		ereport(FATAL,
			(errmsg("unable to allocate memory for struct curl_fetch_st.")));
	}
	fetch->size = 0;

	/* curl init */
	curl_global_init (CURL_GLOBAL_ALL);
	/* get an easy handle */
	if ((eh = curl_easy_init ()) == NULL)
	{
		ereport(FATAL,
			(errmsg("could not instantiate libcurl using curl_easy_init ()")));
	}
	else
	{
          curl_easy_setopt (eh, CURLOPT_ERRORBUFFER, err);
          curl_easy_setopt (eh, CURLOPT_NOSIGNAL, 1);
          curl_easy_setopt (eh, CURL_HTTP_VERSION_1_0, TRUE);
	  curl_easy_setopt (eh, CURLOPT_FAILONERROR, FALSE);
          curl_easy_setopt (eh, CURLOPT_FOLLOWLOCATION, TRUE);
          curl_easy_setopt (eh, CURLOPT_MAXREDIRS, MAXREDIR);
          slist = curl_slist_append(slist, "pragma:");
          curl_easy_setopt (eh, CURLOPT_HTTPHEADER, slist);
          curl_easy_setopt (eh, CURLOPT_URL, url);
          curl_easy_setopt (eh, CURLOPT_TIMEOUT, CURL_TIMEOUT);
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYHOST, FALSE);
          curl_easy_setopt (eh, CURLOPT_SSL_VERIFYPEER, FALSE);
	  curl_easy_setopt (eh, CURLOPT_NOBODY, TRUE);
	  curl_easy_setopt (eh, CURLOPT_HEADERFUNCTION, header_callback);
	  curl_easy_setopt (eh, CURLOPT_HEADERDATA, (void *) fetch);
	  curl_easy_setopt(eh, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	}

	res = curl_easy_perform (eh);
	if (res == CURLE_OK)
	{
		long http_code = 0;
		curl_easy_getinfo(eh, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code >= 400)
		{
			ereport(WARNING,
				(errmsg("Can not get header of remote object \"%s\", HTTP code returned: %lu",
					url, http_code)));
			curl_global_cleanup ();
			PG_RETURN_NULL();
		}
	}
	curl_global_cleanup ();

	/* check data received */
	if (fetch->data == NULL || strlen(fetch->data) == 0)
	{
		free(fetch->data);
		PG_RETURN_NULL();
	}

	/* Split the header into line removing \r\n */
	if (!SplitHeaderLine(fetch->data, &linelist))
	{
		free(fetch->data);
		/* syntax error in name list */
		ereport(ERROR,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("can not get a list of line from header output")));
	}

	if (list_length(linelist) == 0)
		PG_RETURN_NULL();

	initStringInfo(&str);

	if (pg_strncasecmp(format, "text", 4) == 0)
	{
		foreach (lc, linelist)
		{
			const char *line = (const char *) lfirst(lc);
			appendStringInfo(&str, "%s\n", line);
		}
		free(fetch->data);
		list_free(linelist);
		PG_RETURN_TEXT_P(cstring_to_text(str.data));
	}
	else
	{
		bool first = true;

		/* The fist line is the response header, append a field name */
		appendStringInfo(&str, "{\"Response\":");

		/* format to json */
		foreach (lc, linelist)
		{
			const char *line = (const char *) lfirst(lc);
			List       *fieldlist = NULL;

			/* special case for the HTTP response */
			if (first)
			{
				appendStringInfo(&str, "\"%s\"", line);
				first = false;
				continue;
			}

			/* split fieldname and value */
			if (!SplitHeaderField((char *)line, &fieldlist))
				/* syntax error in name list */
				ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("can not extract fieldname/values from header output")));
			if (list_length(fieldlist) >= 1)
				appendStringInfo(&str, ",\"%s\":", (char *) linitial(fieldlist));
			if (list_length(fieldlist) >= 2)
			{
				char *value = (char *) lsecond(fieldlist);
				if (value[0] != '"')
				{
					int i;
					/*
					 * replace any double quote by a single
					 * quote to avoid json syntax error
					 */
					for (i = 0; i < strlen(value); i++)
						if (value[i] == '"')
							value[i] = '\'';
					appendStringInfo(&str, "\"%s\"", value);
				}
				else
					appendStringInfoString(&str, value);
			}
			else
				appendStringInfo(&str, "\"\"");

			list_free(fieldlist);
		}
		list_free(linelist);
		free(fetch->data);
		appendStringInfoChar(&str, '}');

		/* validate json */
		if (str.data)
		{
			text       *result = cstring_to_text(str.data);
#if PG_VERSION_NUM < 170000
			JsonLexContext *lex;
			lex = makeJsonLexContext(result, false);
			pg_parse_json(lex, &nullSemAction);
#else
			JsonLexContext lex;

			makeJsonLexContext(&lex, result, false);
			pg_parse_json(&lex, &nullSemAction);
#endif

			PG_RETURN_TEXT_P(result);
		}
		else
			PG_RETURN_NULL();
	}
}

/* Same as scanner_isspace() but we hve removed the \r in the list */
bool
_isspace(char ch)
{
        /* This must match scan.l's list of {space} characters */
        if (ch == ' ' ||
                ch == '\t' ||
                ch == '\n' ||
                ch == '\r' ||
                ch == '\f')
                return true;
        return false;
}

bool
SplitHeaderLine(char *rawstring, List **namelist)
{
	char       *nextp = rawstring;
	bool       done = false;
	char       separator = '\r';

	*namelist = NIL;

	while (_isspace(*nextp))
		nextp++;                                /* skip leading whitespace */

	if (*nextp == '\0')
		return true;                    /* allow empty string */

	/* At the top of the loop, we are at start of a new identifier. */
	do
	{
		char       *curname;
		char       *endp;

		curname = nextp;
		while (*nextp && *nextp != separator)
			nextp++;
		endp = nextp;

		if (*nextp == separator)
		{
			nextp++;
			while (_isspace(*nextp))
				nextp++;                /* skip leading whitespace for next */
			/* we expect another name, so done remains false */
		}
		else if (*nextp == '\0')
			done = true;
		else
		{
			return false;           /* invalid syntax */
		}

		/* Now safe to overwrite separator with a null */
		*endp = '\0';

		/*
		 * Finished isolating current name --- add it to list
		 */
		if (strlen(curname) > 0)
			*namelist = lappend(*namelist, curname);

		/* Loop back if we didn't reach end of string */
	} while (!done);

	return true;
}

bool
SplitHeaderField(char *rawstring, List **namelist)
{
	char       *nextp = rawstring;
	bool       done = false;
	char       separator = ':';

	*namelist = NIL;

	while (_isspace(*nextp))
		nextp++;                                /* skip leading whitespace */

	if (*nextp == '\0')
		return true;                    /* allow empty string */

	/* At the top of the loop, we are at start of a new identifier. */
	do
	{
		char       *curname;
		char       *endp;

		curname = nextp;
		while (*nextp && *nextp != separator)
			nextp++;
		endp = nextp;

		if (*nextp == separator)
		{
			nextp++;
			while (_isspace(*nextp))
				nextp++;                /* skip leading whitespace for next */
			/* other information is the value and as it can contain : we change the separator */
			separator = '\r';
		}
		else if (*nextp == '\0')
			done = true;
		else
		{
			return false;           /* invalid syntax */
		}

		/* Now safe to overwrite separator with a null */
		*endp = '\0';

		/*
		 * Finished isolating current name --- add it to list
		 */
		if (strlen(curname) > 0)
			*namelist = lappend(*namelist, curname);

		/* Loop back if we didn't reach end of string */
	} while (!done);

	return true;
}
