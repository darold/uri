/*
 * Uri is an extention to store wellformed URI and retrieve URL informations
 * Author: Gilles Darold (gilles@darold.net)
 * Copyright (c) 2015-2022 Gilles Darold - All rights reserved.
 */

/*
 * uri is an extension to add uri data type for postgresql,
 * it allows to insert data in uri format and provide all
 * functions to extract uri parts and compare uris.
 * It has the following operators =, <>, <, <=, >, >=, @>
 * and <@.  
 */

/*
 * Some parts of the code are original code from liburi licensed under the
 * terms of the Apache License, Version 2.0. The code have been embeded to
 * the extension to avoid dependencies requiring compilation from sources.
 * liburi can be found here https://github.com/bbcarchdev/liburi
 *
 *  Copyright (c) 2012 Mo McRoberts
 *  Copyright (c) 2014-2017 BBC
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

/* From liburi */
struct uri_struct
{
	/* A uriparser URI instance */
	UriUriA uri;
	/* Any of the below members may be NULL to indicate absence */
	/* The URI scheme, e.g., 'http' */
	char *scheme;
	/* Authentication data - e.g., 'user:secret' */
	char *auth;
	/* The username portion of auth */
	char *user;
	/* The password portion of auth */
	char *password;
	/* The hostname, as a string */
	char *hoststr;
	/* The hostname as a structure */
	struct UriHostDataStructA hostdata;
	/* The port, as a string */
	char *portstr;
	/* The port parsed as an unsigned integer */
	unsigned int port;
	/* The combined auth, hoststr and portstr comprising the authority or
	 * namespace identifier
	 */
	char *authority;
	/* The namespace-specific segment of a non-hierarchical URI */
	char *nss;
	/* The path; the first segment points to the start of the buffer; the
	 * remaining segments in the list point to sections within that same
	 * buffer.
	 */
	UriPathSegmentA *pathfirst;
	UriPathSegmentA *pathlast;
	/* Is the path absolute? */
	int pathabs;
	/* The current path pointer (used with uri_peek(), uri_consume() and
	 * uri_rewind())
	 */
	UriPathSegmentA *pathcur;
	/* The query-string */
	char *query;
	/* The fragment identifier */
	char *fragment;
	/* The complete URI in normalised form */
	char *composed;
	/* Is this URI absolute? */
	int absolute;
	/* Is this URI hierarchical? (http, file and ftp are; urn, tag and
	 * about aren't)
	*/
	int hier;
};

/* From liburi */
typedef struct uri_struct URI;

char *get_filetype(char *filename);
bool is_real_file(char *filename);
char *uriToStr(const char *url);
bool _isspace(char ch);
bool SplitHeaderLine(char *rawstring, List **namelist);
bool SplitHeaderField(char *rawstring, List **namelist);

/* Functions extracted from liburi */
int uri_destroy(URI *uri);
int uri_reset_(URI *uri);
URI * uri_create_(void);
static const char *uri_schemeend_(const char *str);
static char *uri_range_copy_(const UriTextRangeA *range);
static int uri_range_set_(UriTextRangeA *range, const char *src);
static int uri_path_copy_ref_(UriPathSegmentA **head, UriPathSegmentA **tail, const UriPathSegmentA *src);
int uri_postparse_set_(URI *uri);
int uri_postparse_(URI *uri);
int uri_rebase(URI *restrict reluri, const URI *restrict base);

/* Function copied from liburi (https://github.com/bbcarchdev/liburi) */
URI *uri_create_str(const char *restrict str, const URI *restrict base);
size_t uri_str(const URI *restrict uri, char *restrict buf, size_t buflen);
size_t uri_scheme(const URI *restrict uri, char *restrict buf, size_t buflen);
size_t uri_auth(const URI *restrict uri, char *restrict buf, size_t buflen);
size_t uri_host(const URI *restrict uri, char *restrict buf, size_t buflen);
size_t uri_port(const URI *restrict uri, char *restrict buf, size_t buflen);
int uri_portnum(const URI *uri);
size_t uri_path(const URI *restrict uri, char *restrict buf, size_t buflen);
size_t uri_query(const URI *restrict uri, char *restrict buf, size_t buflen);
size_t uri_fragment(const URI *restrict uri, char *restrict buf, size_t buflen);
int uri_absolute(const URI *uri);
int uri_absolute_path(const URI *uri);
int uri_equal(const URI *a, const URI *b);
int uri_hostdata_copy_(struct UriHostDataStructA *restrict dest, const struct UriHostDataStructA *restrict src);
int uri_path_copy_(URI *uri, const UriPathSegmentA *head);
static int uri_addch_(int ch, char *restrict *restrict buf, size_t *restrict buflen);
static size_t uri_wctoutf8_(int *dest, wchar_t ch);
static size_t uri_encode_8bit_(char *dest, unsigned char ch);
static size_t uri_encode_wide_(char *dest, wchar_t ch);
static size_t uri_widebytes_(const char *uristr, size_t nbytes);
static int uri_preprocess_(char *restrict buf, const char *restrict uristr, size_t nbytes);
static int uri_preprocess_utf8_(char *restrict buf, const unsigned char *restrict uristr, size_t nbytes);
URI *uri_create_ustr(const unsigned char *restrict ustr, const URI *restrict base);
URI *uri_create_ascii(const char *restrict str, const URI *restrict base);


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

/* Destroy a URI object */
int
uri_destroy(URI *uri)
{
	if(uri)
	{
		uri_reset_(uri);
		free(uri);
	}
	return 0;
}

/*Safely free the contents of a URI object, so that they can be replaced */
int
uri_reset_(URI *uri)
{
	UriPathSegmentA *seg, *next;

	uriFreeUriMembersA(&(uri->uri));
	free(uri->scheme);
	free(uri->auth);
	free(uri->user);
	free(uri->password);
	free(uri->hoststr);
	free(uri->hostdata.ip4);
	free(uri->hostdata.ip6);
	free((char *) uri->hostdata.ipFuture.first);
	free(uri->portstr);
	free(uri->authority);
	free(uri->nss);
	for (seg = uri->pathfirst; seg; seg = next)
	{
		next = seg->next;
		free((char *) seg->text.first);
		free(seg);
	}
	free(uri->query);
	free(uri->fragment);
	free(uri->composed);
	memset(uri, 0, sizeof(URI));

	return 0;
}

/* Allocate a new URI object */
URI *
uri_create_(void)
{
	URI *p;
	p = (URI *) calloc(1, sizeof(URI));
	if(!p)
		return NULL;

	return p;
}

/*
 * Find the first character after the URI scheme; this function will
 * therefore return either NULL, or a pointer to a colon.
 */
static const char *
uri_schemeend_(const char *str)
{
	for(; str && *str; str++)
	{
		if (*str == ':')
			return str;

		/*
		 * These characters cannot appear within a scheme, and so
		 * indicate that the scheme is absent.
		 */
		if (*str == '@' || *str == '/' || *str == '%' || *str == '\\')
			break;
	}
	return NULL;
}

/* Copy a UriTextRange to a newly-allocated buffer */
static char *
uri_range_copy_(const UriTextRangeA *range)
{
	size_t l;
	char *buf;

	if (range->first && range->afterLast)
		l = range->afterLast - range->first + 1;
	else if (range->first)
		l = strlen(range->first) + 1;
	else
	{
		errno = 0;
		return NULL;
	}

	if (!l)
	{
		errno = 0;
		return NULL;
	}
	buf = (char *) malloc(l);

	if (!buf)
		return NULL;

	strncpy(buf, range->first, l);
	buf[l - 1] = 0;

	return buf;
}

/*
 * Free a UriTextRange if it's owned by the UriUri, and then
 * set it to point to the supplied null-terminated string. Note that
 * uri->owner must be set to URI_FALSE after calling this or else
 * uriFreeUriMembersA() will free heap blocks it doesn't own.
 * src may be NULL. owner must be uri->owner.
 */
static int
uri_range_set_(UriTextRangeA *range, const char *src)
{
	/*
	 * Set the range to point to the entire length of src (provided src
	 * is non-NULL)
	 */
	range->first = src;
	if (src)
		range->afterLast = strchr(src, 0);
	else
		range->afterLast = NULL;

	return 0;
}

/* Create a new chain of path segments referencing the
 * strings in the source segment; this is used because even if
 * UriUriA::owner is false, the segments themselves will still be
 * freed by uriFreeUriMembersA().
 */
static int
uri_path_copy_ref_(UriPathSegmentA **head, UriPathSegmentA **tail, const UriPathSegmentA *src)
{
	UriPathSegmentA *seg, *prev;

	prev = NULL;
	for (; src; src = src->next)
	{
		seg = (UriPathSegmentA *) calloc(1, sizeof(UriPathSegmentA));
		if (!seg)
			return -1;

		seg->text.first = src->text.first;
		seg->text.afterLast = src->text.afterLast;
		if (prev)
			prev->next = seg;
		else
			*head = seg;
		prev = seg;
	}
	*tail = prev;

	return 0;
}

/* Copy a UriHostData struct, allocating memory as needed */
int
uri_hostdata_copy_(struct UriHostDataStructA *restrict dest, const struct UriHostDataStructA *restrict src)
{
	if (src->ip4)
	{
		dest->ip4 = (UriIp4 *) calloc(1, sizeof(UriIp4));
		if (!dest->ip4)
			return -1;
		memcpy(dest->ip4, src->ip4, sizeof(UriIp4));
	}
	if (src->ip6)
	{
		dest->ip6 = (UriIp6 *) calloc(1, sizeof(UriIp6));
		if (!dest->ip6)
			return -1;
		memcpy(dest->ip6, src->ip6, sizeof(UriIp6));
	}
	return 0;
}

/*
 * Replace the members of a UriUriA with pointers to our own buffers
 * excepting ip4 and ip6 within the hostData member, which is always
 * duplicated.
 */
int
uri_postparse_set_(URI *uri)
{
	uriFreeUriMembersA(&(uri->uri));
	uri->uri.owner = URI_FALSE;
	uri_range_set_(&(uri->uri.scheme), uri->scheme);
	uri_range_set_(&(uri->uri.userInfo), uri->auth);
	uri_range_set_(&(uri->uri.hostText), uri->hoststr);
	uri_range_set_(&(uri->uri.portText), uri->portstr);
	uri_range_set_(&(uri->uri.query), uri->query);
	uri_range_set_(&(uri->uri.fragment), uri->fragment);
	uri_range_set_(&(uri->uri.hostData.ipFuture), uri->hostdata.ipFuture.first);
	uri_hostdata_copy_(&(uri->uri.hostData), &(uri->hostdata));
	uri_path_copy_ref_(&(uri->uri.pathHead), &(uri->uri.pathTail), uri->pathfirst);
	uri->uri.absolutePath = (uri->pathabs ? URI_TRUE : URI_FALSE);

	return 0;
}

/* Copy a UriPath into our URI object */
int
uri_path_copy_(URI *uri, const UriPathSegmentA *head)
{
	UriPathSegmentA *seg, *prev;

	prev = NULL;
	uri->pathabs = (int) uri->uri.absolutePath;
	for (; head; head = head->next)
	{
		seg = (UriPathSegmentA *) calloc(1, sizeof(UriPathSegmentA));
		if (!seg)
			return -1;

		seg->text.first = uri_range_copy_(&(head->text));
		if (seg->text.first)
			seg->text.afterLast = strchr(seg->text.first, 0);
		if (prev)
			prev->next = seg;
		else
			uri->pathfirst = seg;
		prev = seg;
	}
	uri->pathlast = prev;
	uri->pathcur = uri->pathfirst;
	return 0;
}

/* Perform post-parsing normalisation and manipulation of a URI */
int
uri_postparse_(URI *uri)
{
	uriNormalizeSyntaxA(&(uri->uri));

	/* Copy the UriUriA text ranges into new buffers, then set the
	 * ranges to point back to our new buffers. This means that the uriparser
	 * APIs will still work on our UriUriA object, but we can manipulate the
	 * components as needed.
	 *
	 * The UriUriA's owner flag will be set to false, indicating that with the
	 * exception of the ip4 and ip6 structs within its hostData, it does not
	 * own any of the memory its text ranges point at.
	 */
	uri->scheme = uri_range_copy_(&(uri->uri.scheme));
	if (uri->scheme)
		uri->absolute = 1;

	uri->auth = uri_range_copy_(&(uri->uri.userInfo));
	uri->hoststr = uri_range_copy_(&(uri->uri.hostText));
	uri->portstr = uri_range_copy_(&(uri->uri.portText));
	uri->query = uri_range_copy_(&(uri->uri.query));
	uri->fragment = uri_range_copy_(&(uri->uri.fragment));
	/* Copy the path data */
	if (uri_path_copy_(uri, uri->uri.pathHead))
		return -1;

	/* Copy the host data */
	if ((uri->hostdata.ipFuture.first = uri_range_copy_(&(uri->uri.hostData.ipFuture))))
		uri->hostdata.ipFuture.afterLast = strchr(uri->hostdata.ipFuture.first, 0);

	if (uri_hostdata_copy_(&(uri->hostdata), &(uri->uri.hostData)))
		return -1;

	/* Parse the port number, if present */
	if (uri->portstr)
	{
		uri->port = atoi(uri->portstr);
		if (uri->port < 1 || uri->port > 65535)
			uri->port = 0;
	}
	return uri_postparse_set_(uri);
}

/*
 * Rebase reluri against the given base. If reluri is already absolute,
 * or base is NULL, this is a no-op. This function will modifiy reluri;
 * if this is not desirable, duplicate it first with uri_create_uri().
 */
int
uri_rebase(URI *restrict reluri, const URI *restrict base)
{
	URI abstemp;

	memset(&abstemp, 0, sizeof(URI));

	/* Either no base provided (no-op), or reluri is already absolute. */
	if (!base || reluri->absolute)
		return 0;

	/* Rebasing failed */
	if (uriAddBaseUriA(&(abstemp.uri), &(reluri->uri), &(base->uri)) != URI_SUCCESS)
		return -1;

	/* Rebasing didn't result in a new URI */
	if (uriEqualsUriA(&(abstemp.uri), &(reluri->uri)) == URI_TRUE)
	{
		uriFreeUriMembersA(&(abstemp.uri));
		return 0;
	}
	uri_postparse_(&abstemp);

	/*
	 * Free the resources used by reluri, replace its contents with that
	 * from absolute.
	 */
	uri_reset_(reluri);
	memcpy(reluri, &abstemp, sizeof(URI));

	return 0;
}

/*
 * Create a URI from a 7-bit ASCII string, which we consider to be the
 * native form.
 * Use uri_create_str(), uri_create_wstr(), or uri_create_ustr() if the
 * source string is not plain ASCII.
 */
URI *
uri_create_ascii(const char *restrict str, const URI *restrict base)
{
	URI *uri;
	UriParserStateA state;
	const char *t;

	uri = uri_create_();
	if (!uri)
		return NULL;
	/* Deal with non-hierarchical URIs properly:
	 * Scan the string for the end of the scheme, If the character immediately
	 * following the colon is not a slash, we consider the URI
	 * non-hierarchical and parse it accordingly.
	 */
	t = uri_schemeend_(str);
	if (t && t[0] && t[1] != '/' && t[1] != '\\')
	{
		/* A scheme is present and the first character after the colon
		 * is not slash
		 */
		//uri->hier = 0;
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("non-hierarchical URI are not supported: \%s\"", str)));
		//return NULL;
	}
	else
	{
		uri->hier = 1;
		state.uri = &(uri->uri);
		if (uriParseUriA(&state, str) != URI_SUCCESS)
		{
			uri_destroy(uri);
			return NULL;
		}
	}
	if(uri_postparse_(uri))
	{
		uri_destroy(uri);
		return NULL;
	}
	if(uri_rebase(uri, base))
	{
		uri_destroy(uri);
		return NULL;
	}
	return uri;
}

/* Encode an 8-bit character as a percent-encoded sequence */
static size_t
uri_encode_8bit_(char *dest, unsigned char ch)
{
	static const char hexdig[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};

	*dest = '%';
	dest++;
	*dest = hexdig[ch >> 4];
	dest++;
	*dest = hexdig[ch & 15];
	dest++;
	return 3;
}

/*
 * Map a potential IRI to a URI (see section 3.1 of RFC3987), percent-encoding
 * UTF-8 characters as we do
 */
static int
uri_preprocess_utf8_(char *restrict buf, const unsigned char *restrict uristr, size_t nbytes)
{
	unsigned char ch;
	char *bp;

	/* Reset the multibyte shift state */
	for (bp = buf; nbytes && *uristr;)
	{
		/* Convert the next character sequence into a wide character */
		ch = *uristr;
		if(ch < 33 || ch > 127)
		{
			/* If the character is outside of the ASCII printable range,
			 * replace it with a percent-encoded UTF-8 equivalent
			 */
			bp += uri_encode_8bit_(bp, ch);
		}
		else
		{
			*bp = ch;
			bp++;
		}
		uristr++;
		nbytes--;
	}
	*bp = 0;
	return 0;
}

/*
 * Create a URI from a UTF-8-encoded string; any non-ASCII characters
 * will be percent-encoded
 */
URI *
uri_create_ustr(const unsigned char *restrict ustr, const URI *restrict base)
{
        const unsigned char *t;
        char *buf;
        size_t l, needed;
        URI *uri;

        /* Determine the required buffer size, accounting for percent-encoding
         * of non-printable and non-ASCII characters
         */
        l = strlen((const char *) ustr);
        needed = l + 1;
        for (t = ustr; *t; t++)
        {
                if(*t < 33 || *t > 127)
                        needed += 2;
        }
        buf = (char *) calloc(1, needed);
        if (!buf)
                return NULL;
        if (uri_preprocess_utf8_(buf, ustr, l))
        {
                free(buf);
                return NULL;
        }
        uri = uri_create_ascii(buf, base);
        free(buf);
        return uri;
}

/* Scan the URI string for wide characters and return the maximum storage
 * needed for their UTF-8 encoding
 */
static size_t
uri_widebytes_(const char *uristr, size_t nbytes)
{
	wchar_t ch;
	int r;
	const char *p;
	size_t numwide;

	mbtowc(&ch, NULL, 0);
	numwide = 0;
	for (p = uristr; *p;)
	{
		r = mbtowc(&ch, p, nbytes);
		if(r <= 0)
			return (size_t) -1;
		if(ch < 33 || ch > 127)
		{
			/* Account for the full 6 bytes of UTF-8: we can't assume that
			 * the source string (and hence the return value of mbtowc()) is
			 * itself UTF-8, as it's locale-dependent.
			 */
			numwide += 6;
		}
		p += r;
	}
	return numwide;
}

/* Encode ch as UTF-8, storing it in dest[0..3] and returning the number
 * of octets stored. Because this is a convenience function used by
 * uri_encode_wide_(), dest is an array of ints, rather than unsigned chars.
 */
static size_t
uri_wctoutf8_(int *dest, wchar_t ch)
{
	if(ch < 0x7f)
	{
		dest[0] = ch;
		return 1;
	}
	if(ch < 0x07ff)
	{
		/* 110aaaaa 10bbbbbb */
		dest[0] = 0xc0 | ((ch & 0x0007c0) >>  6);
		dest[1] = 0x80 | (ch & 0x00003f);
		return 2;
	}
	if(ch < 0xffff)
	{
		/* 1110aaaa 10bbbbbb 10cccccc */
		dest[0] = 0xe0 | ((ch & 0x00f000) >> 12);
		dest[1] = 0x80 | ((ch & 0x000fc0) >> 6);
		dest[2] = 0x80 | (ch & 0x00003f);
		return 3;
	}
	/* 11110aaa 10bbbbbb 10cccccc 10dddddd */
	dest[0] = 0xf0 | ((ch & 0x1c0000) >> 18);
	dest[1] = 0x80 | ((ch & 0x03f000) >> 12);
	dest[2] = 0x80 | ((ch & 0x000fc0) >>  6);
	dest[3] = 0x80 | (ch & 0x00003f);
	return 4;
}

/*
 * Encode a Unicode wide-character as a sequence of percent-encoded
 * UTF-8.
 */
static size_t
uri_encode_wide_(char *dest, wchar_t ch)
{
	static const char hexdig[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};

	int utf8[6];
	size_t l, c;

	l = uri_wctoutf8_(utf8, ch);
	for(c = 0; c < l; c++)
	{
		*dest = '%';
		dest++;
		*dest = hexdig[utf8[c] >> 4];
		dest++;
		*dest = hexdig[utf8[c] & 15];
		dest++;
	}
	return l * 3;
}

/*
 * Map a potential IRI to a URI (see section 3.1 of RFC3987), converting
 * from locale-specific multibyte encoding to wide characters as we do
 */
static int
uri_preprocess_(char *restrict buf, const char *restrict uristr, size_t nbytes)
{
	wchar_t ch;
	char *bp;
	int r;

	/* Reset the multibyte shift state */
	mbtowc(&ch, NULL, 0);
	r = 0;
	for(bp = buf; nbytes && *uristr;)
	{
		/* Convert the next character sequence into a wide character */
		r = mbtowc(&ch, uristr, nbytes);
		if(r <= 0)
		{
			return -1;
		}
		if(ch < 33 || ch > 127)
		{
			/*
			 * If the character is outside of the ASCII printable range,
			 * replace it with a percent-encoded UTF-8 equivalent
			 */
			bp += uri_encode_wide_(bp, ch);
		}
		else
		{
			*bp = ch;
			bp++;
		}
		uristr += r;
		nbytes -= r;
	}
	*bp = 0;
	return 0;
}

/* Create a URI from a string in the current locale */
URI *
uri_create_str(const char *restrict uristr, const URI *restrict base)
{
	char *buf;
	URI *uri;
	size_t l, numwide;

	/* XXX We should do this via mbstowcs() and then uri_create_wstr() */
	l = strlen(uristr) + 1;
	numwide = uri_widebytes_(uristr, l);
	buf = (char *) malloc(l + numwide * 3);
	if (!buf)
		return NULL;
	if (uri_preprocess_(buf, uristr, l))
	{
		free(buf);
		return NULL;
	}
	uri = uri_create_ascii(buf, base);
	free(buf);
	return uri;
}

size_t
uri_str(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	int bufsize;

	if (uriToStringCharsRequiredA(&(uri->uri), &bufsize) != URI_SUCCESS)
		return (size_t) -1;
	bufsize++;
	if (buf && buflen)
	{
		if(uriToStringA(buf, &(uri->uri), buflen, NULL) != URI_SUCCESS)
			return (size_t) -1;
		buf[buflen - 1] = 0;
	}
	return bufsize;
}

char *
uriToStr(const char *url)
{
	URI     *uri;
	char    *buffer = NULL;
	size_t  needed;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	needed = uri_str(uri, NULL, 0);
	if (!needed)
		return NULL;
	if((buffer = (char *) malloc(needed)) == NULL ||
		uri_str(uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get string from URI: \%s\"", url)));
	}
	uri_destroy(uri);

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

size_t
uri_scheme(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	if (!uri->scheme)
	{
		if(buf && buflen)
			*buf = 0;
		return 0;
	}
	if(buf && buflen)
	{
		strncpy(buf, uri->scheme, buflen - 1);
		buf[buflen - 1] = 0;
	}
	return strlen(uri->scheme) + 1;
}

PG_FUNCTION_INFO_V1(uri_get_scheme);
Datum
uri_get_scheme(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[8];
	URI	*uri;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	uri_scheme(uri, buffer, 8);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

size_t
uri_auth(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	if(!uri->auth)
	{
		if(buf && buflen)
			*buf = 0;
		return 0;
	}
	if(buf && buflen)
	{
		strncpy(buf, uri->auth, buflen - 1);
		buf[buflen - 1] = 0;
	}
	return strlen(uri->auth) + 1;
}

PG_FUNCTION_INFO_V1(uri_get_auth);
Datum
uri_get_auth(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	char    *buffer = NULL;
	size_t needed; 

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	needed = uri_auth(uri, NULL, 0);
	if(!needed)
		PG_RETURN_NULL();

	if((buffer = (char *) malloc(needed)) == NULL ||
		uri_auth(uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get auth part from URI: \"%s\"", url)));
	}
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

size_t
uri_host(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	if(!uri->hoststr)
	{
		if(buf && buflen)
			*buf = 0;
		return 0;
	}
	if(buf && buflen)
	{
		strncpy(buf, uri->hoststr, buflen - 1);
		buf[buflen - 1] = 0;
	}
	return strlen(uri->hoststr) + 1;
}

PG_FUNCTION_INFO_V1(uri_get_host);
Datum
uri_get_host(PG_FUNCTION_ARGS)
{
	char    *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	char    *buffer = NULL;
	size_t  needed; 

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	needed = uri_host(uri, NULL, 0);
	if (!needed)
		PG_RETURN_NULL();
	if ((buffer = (char *) malloc(needed)) == NULL ||
		uri_host(uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get host part from URI: \"%s\"", url)));
	}
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));
}

size_t
uri_port(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	if (!uri->portstr)
	{
		if(buf && buflen)
			*buf = 0;
		return 0;
	}
	if(buf && buflen)
	{
		strncpy(buf, uri->portstr, buflen - 1);
		buf[buflen - 1] = 0;
	}
	return strlen(uri->portstr) + 1;
}

PG_FUNCTION_INFO_V1(uri_get_port);
Datum
uri_get_port(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[6];
	URI	*uri;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	uri_port(uri, buffer, 6);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

/* Return the port as a parsed integer */
int
uri_portnum(const URI *uri)
{
	return (int) uri->port;
}

PG_FUNCTION_INFO_V1(uri_get_portnum);
Datum
uri_get_portnum(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	int	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_portnum(uri);
        uri_destroy(uri);

	PG_RETURN_INT16(r);

}

/* Add a single character to buf, provided it has space */
static int
uri_addch_(int ch, char *restrict *restrict buf, size_t *restrict buflen)
{
	if (*buf && *buflen)
	{
		**buf = ch;
		(*buf)++;
		**buf = 0;
		(*buflen)--;
	}
	return 1;
}

size_t
uri_path(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	size_t total, len;
	UriPathSegmentA *p;

	if (!uri->uri.pathHead && !uri->uri.absolutePath)
	{
		if(buf && buflen)
			*buf = 0;
		return 0;
	}
	total = 0;
	if (uri_absolute_path(uri))
	{
		uri_addch_('/', &buf, &buflen);
		total++;
	}
	if (buf && buflen)
		*buf = 0;
	for(p = uri->pathfirst; p; p = p->next)
	{
		if(p != uri->pathfirst)
		{
			uri_addch_('/', &buf, &buflen);
			total++;
		}
		if(!p->text.first)
			return (size_t) -1;
		if(!p->text.first[0])
			continue;
		len = strlen(p->text.first) + 1;
		if(buf)
		{
			strncpy(buf, p->text.first, buflen - 1);
			buf[buflen - 1] = 0;
		}
		len--;
		total += len;
		if(buflen < len)
		{
			buflen = 0;
			buf = NULL;
		}
		else
		{
			if(buf)
				buf += len;
			buflen -= len;
		}
	}
	return total + 1;
}

PG_FUNCTION_INFO_V1(uri_get_path);
Datum
uri_get_path(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	char    *buffer = NULL;
	size_t needed;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	needed = uri_path(uri, NULL, 0);
	if (!needed)
		PG_RETURN_NULL();
	if ((buffer = (char *) malloc(needed)) == NULL ||
		uri_path(uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get path part from URI: \"%s\"", url)));
	}
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

size_t
uri_query(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	if(!uri->query)
	{
		if(buf && buflen)
			*buf = 0;
		return 0;
	}
	if(buf && buflen)
	{
		strncpy(buf, uri->query, buflen - 1);
		buf[buflen - 1] = 0;
	}
	return strlen(uri->query) + 1;
}

PG_FUNCTION_INFO_V1(uri_get_query);
Datum
uri_get_query(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	char    *buffer = NULL;
	size_t needed; 

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	needed = uri_query(uri, NULL, 0);
	if (!needed)
		PG_RETURN_NULL();
	if ((buffer = (char *) malloc(needed)) == NULL ||
		uri_query(uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get query part from URI: \"%s\"", url)));
	}
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));
}

size_t
uri_fragment(const URI *restrict uri, char *restrict buf, size_t buflen)
{
	if(!uri->fragment)
	{
		if(buf && buflen)
			*buf = 0;
		return 0;
	}
	if(buf && buflen)
	{
		strncpy(buf, uri->fragment, buflen - 1);
		buf[buflen - 1] = 0;
	}
	return strlen(uri->fragment) + 1;
}

PG_FUNCTION_INFO_V1(uri_get_fragment);
Datum
uri_get_fragment(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	char    *buffer = NULL;
	size_t needed; 

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	needed = uri_fragment(uri, NULL, 0);
	if (!needed)
		PG_RETURN_NULL();
	if ((buffer = (char *) malloc(needed)) == NULL ||
		uri_fragment(uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get fragment part from URI: \"%s\"", url)));
	}
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

/* Return 1 if a URI is absolute, 0 otherwise */
int
uri_absolute(const URI *uri)
{
	return (uri->absolute ? 1 : 0);
}

PG_FUNCTION_INFO_V1(uri_is_absolute);
Datum
uri_is_absolute(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	int	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_absolute(uri);
        uri_destroy(uri);

	PG_RETURN_BOOL(r);

}

/* Return 1 if the URI's path is absolute, 0 otherwise */
int
uri_absolute_path(const URI *uri)
{
	return uri->pathabs || (uri->absolute && !uri->hier) || uri->hoststr;
}

PG_FUNCTION_INFO_V1(uri_is_absolute_path);
Datum
uri_is_absolute_path(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	int	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_absolute_path(uri);
        uri_destroy(uri);

	PG_RETURN_BOOL(r);

}

PG_FUNCTION_INFO_V1(uri_get_str);
Datum
uri_get_str(PG_FUNCTION_ARGS)
{
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));

	PG_RETURN_TEXT_P(cstring_to_text(uriToStr(url)));
}

/* Compare two URIs and test for equality */
int
uri_equal(const URI *a, const URI *b)
{
	return uriEqualsUriA(&(a->uri), &(b->uri));
}

PG_FUNCTION_INFO_V1(uri_is_equal);
Datum
uri_is_equal(PG_FUNCTION_ARGS)
{
	char   *url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char   *url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
	URI	*uri1;
	URI	*uri2;
	int	r;

	uri1 = uri_create_str(url1, NULL);
	if (!uri1)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url1)));
	}

	uri2 = uri_create_str(url2, NULL);
	if (!uri2)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url2)));
	}
	r = uri_equal(uri1, uri2);
        uri_destroy(uri1);
        uri_destroy(uri2);

	PG_RETURN_BOOL(r);
}

PG_FUNCTION_INFO_V1(uri_is_notequal);
Datum
uri_is_notequal(PG_FUNCTION_ARGS)
{
	char   *url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char   *url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
	URI	*uri1;
	URI	*uri2;
	int	r;

	uri1 = uri_create_str(url1, NULL);
	if (!uri1)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url1)));
	}

	uri2 = uri_create_str(url2, NULL);
	if (!uri2)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url2)));
	}
	r = uri_equal(uri1, uri2);
        uri_destroy(uri1);
        uri_destroy(uri2);

	if (r == 0)
		PG_RETURN_BOOL(1);
	else
		PG_RETURN_BOOL(0);

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
	char   *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char		localpath[MAXPGPATH];
	URI		*uri;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	uri_path(uri, localpath, MAXPGPATH);
        uri_destroy(uri);

	PG_RETURN_BOOL(is_real_file(localpath));
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
	URI     *h_uri;
	URI     *b_uri;
	char    *buffer;
	size_t  needed;

	/*
	 * When base is a path only append file:// before,
	 * uri_rebase only supports URL
	 */
	if (base[0] == '/')
	{
		char *tmp_str = palloc0(sizeof(char)*(strlen(base)+8));
		strcpy(tmp_str, "file://");
		strcat(tmp_str, base);
		pfree(base);
		base = palloc0(sizeof(char)*strlen(tmp_str));
		strcpy(base, tmp_str);
	}

	b_uri = uri_create_str(base, NULL);
	if (!b_uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", base)));
	}
	h_uri = uri_create_str(url, NULL);
	if (!h_uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	if (uri_rebase(h_uri, b_uri))
	{
		uri_destroy(h_uri);
		PG_RETURN_NULL();
	}
        uri_destroy(b_uri);

	buffer = NULL;
	needed = uri_str(h_uri, NULL, 0);
	if(!needed ||
		(buffer = (char *) malloc(needed)) == NULL ||
		uri_str(h_uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(h_uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get string from rebased URI: \"%s\" on base \"%s\"", url, base)));
	}
        uri_destroy(h_uri);

	PG_RETURN_POINTER((t_uri *) cstring_to_text(buffer));
}

PG_FUNCTION_INFO_V1(uri_localpath_size);
Datum
uri_localpath_size(PG_FUNCTION_ARGS)
{
	char        *url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char         localpath[MAXPGPATH];
	char        *dstpath;
	URI         *uri;
	struct stat  statbuf;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	uri_path(uri, localpath, MAXPGPATH);
        uri_destroy(uri);

        /* Does the corresponding local file exists? */
	dstpath = realpath(localpath, NULL);
	if (dstpath == NULL)
	{
                if (errno != ENOENT)
		{
			int save_errno = errno;
			ereport(ERROR, (
				errmsg("could not get real path of file \"%s\": %s",
						localpath, strerror(save_errno))));
		}
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
						localpath, strerror(save_errno))));
		}
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
					localpath)));
			PG_RETURN_NULL();
			break;
		}
	}

	PG_RETURN_INT64(statbuf.st_size);

}

PG_FUNCTION_INFO_V1(uri_remotepath_exists);
Datum
uri_remotepath_exists(PG_FUNCTION_ARGS)
{
	char	*url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	bool	exists;
	struct curl_slist *slist = NULL;
	CURL *eh = NULL;        /* libcurl handler */
	CURLcode res ;
	char err[CURL_ERROR_SIZE];

	uri = uri_create_str(url, NULL);
	if (!uri)
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
        uri_destroy(uri);

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
	char		*url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI		*uri;
	struct curl_slist *slist = NULL;
	CURL *eh = NULL;        /* libcurl handler */
	CURLcode res ;
	char err[CURL_ERROR_SIZE];
	double filesize = 0.0;

	uri = uri_create_str(url, NULL);
	if (!uri)
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
        uri_destroy(uri);

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
		res = curl_easy_getinfo(eh, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);
		if ((res != CURLE_OK) || (filesize < 0.0))
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
	char		*url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI		*uri;
	struct curl_slist *slist = NULL;
	CURL *eh = NULL;        /* libcurl handler */
	CURLcode res ;
	char err[CURL_ERROR_SIZE];
	char *content_type = NULL;

	uri = uri_create_str(url, NULL);
	if (!uri)
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
        uri_destroy(uri);

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
	char	*url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	char    *mime;
	char    *buffer = NULL;
	size_t  needed; 

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	needed = uri_path(uri, NULL, 0);
	if (!needed)
		PG_RETURN_NULL();
	if ((buffer = (char *) malloc(needed)) == NULL ||
		uri_path(uri, buffer, needed) != needed)
	{
		free(buffer);
		uri_destroy(uri);
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to get path part from URI: \"%s\"", url)));
	}
        uri_destroy(uri);

	if (!is_real_file(buffer))
		PG_RETURN_NULL();

	mime = get_filetype(buffer);

	PG_RETURN_TEXT_P(cstring_to_text(mime));

}

PG_FUNCTION_INFO_V1(uri_escape);
Datum
uri_escape(PG_FUNCTION_ARGS)
{
	char		*url = TextDatumGetCString(PG_GETARG_DATUM(0));
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
	char		*url = TextDatumGetCString(PG_GETARG_DATUM(0));
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
	UriParserStateA stateB;
	UriUriA  b_uri;
	UriParserStateA stateH;
	UriUriA  h_uri;
	UriUriA  p_uri;
	int      rc;
	char     *buffer = NULL;
	char     *found = strcasestr(base, "file:///");
	int      needed;

	/*
	 * With a base starting with file:// and a path only as url
	 * we need to remove the scheme from the base
	 */
	if (url[0] == '/' && found != NULL && (found - base) == 0)
		base += 7;

	stateB.uri = &b_uri;
	if (uriParseUriA(&stateB, base) != URI_SUCCESS)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", base)));
	}

	stateH.uri = &h_uri;
	if (uriParseUriA(&stateH, url) != URI_SUCCESS)
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
	char		*url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char		*format = TextDatumGetCString(PG_GETARG_DATUM(1));
	URI		*uri;
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

	uri = uri_create_str(url, NULL);
	if (!uri)
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
        uri_destroy(uri);

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
	  /* add header callback function */
	  curl_easy_setopt (eh, CURLOPT_HEADERFUNCTION, header_callback);
	  /* pass fetch struct pointer */
	  curl_easy_setopt (eh, CURLOPT_HEADERDATA, (void *) fetch);
	  /* set default user agent */
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

