/* *
 * Uri is an extention to store wellformed URI and retrieve URL informations
 * Author: Gilles Darold (gilles@darold.net)
 * Copyright (c) 2015-2020 Gilles Darold - All rights reserved.
 * */

/* *
 *
 * uri is an extension to add uri data type for postgresql,
 * it allows to insert data in uri format and provide all
 * functions to extract uri parts and compare uris.
 * It has the following operators =, <>, <, <=, >, >=, @>
 * and <@.  
 *
 * */

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
#include <liburi.h>
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

char *get_filetype(char *filename);
bool is_real_file(char *filename);
char *uriToStr(const char *url);
bool _isspace(char ch);
bool SplitHeaderLine(char *rawstring, List **namelist);
bool SplitHeaderField(char *rawstring, List **namelist);


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

		if (str.data)
		{
			text       *result = cstring_to_text(str.data);
			JsonLexContext *lex;

			/* validate it */
			lex = makeJsonLexContext(result, false);
			pg_parse_json(lex, &nullSemAction);

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

