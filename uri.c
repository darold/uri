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

#include <postgres.h>
#include <common/fe_memutils.h>
#include <access/hash.h>
#include <fmgr.h>
#include <catalog/pg_type.h>
#include <utils/builtins.h>
#include <libpq/pqformat.h>

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
char *get_filetype(char *filename);
bool is_real_file(char *filename);
char *uriToStr(const char *url);


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

	if (strstr(uriToStr(url1), uriToStr(url2)) != NULL)
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
	int      needed;

	/*
	 * With a base starting with file:// and a path only as url
	 * we need to remove the scheme from the base
	 */
	if (url[0] == '/' && strstr(base, "file:///") != NULL)
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
