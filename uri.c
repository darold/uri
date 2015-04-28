/*  Gilles Darold (gilles@darold.net)
 *
 * uri is an extention to store wellformed URI
 * and retrieve URL informations
 *
 * */


/*
 * uri is a extension to add uri data type for postgresql,
 * it allows to insert data in uri format and provide all
 * functions to extract uri parts and compare uris.
 * It has the following operators =, <>, <, <=, >, >=, @>
 * and <@.  
 *
 * */

#include "postgres.h"
#include "fmgr.h"
#include "libpq/pqformat.h"
#include "string.h"
#include "catalog/pg_type.h"
#include "utils/builtins.h"
#include <liburi.h>
#include <sys/stat.h>

#define BUFFER_SIZE 8192
#define DatumGetUri(X) ((uritype *) PG_DETOAST_DATUM_PACKED(X))
#define GETARG_URI(n)  DatumGetUri(PG_GETARG_DATUM(n))

typedef struct varlena t_uri;
int search_str(char src[], char search[]);

/*
 * Declaration of the URI data type function
 */
 
PG_MODULE_MAGIC;
Datum		uri_in(PG_FUNCTION_ARGS);
Datum		uri_out(PG_FUNCTION_ARGS);
Datum		uri_recv(PG_FUNCTION_ARGS);
Datum		uri_send(PG_FUNCTION_ARGS);
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
Datum		uri_rebase(PG_FUNCTION_ARGS);
Datum		uri_localpath_exists(PG_FUNCTION_ARGS);
Datum		uri_localpath_size(PG_FUNCTION_ARGS);


PG_FUNCTION_INFO_V1(uri_in);
Datum
uri_in(PG_FUNCTION_ARGS)
{
	char	*url = PG_GETARG_CSTRING(0);
	char    buffer[BUFFER_SIZE];
	URI     *h_uri;
	size_t  r;

	h_uri = uri_create_str(url, NULL);
	if (!h_uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_str(h_uri, buffer, BUFFER_SIZE);
        uri_destroy(h_uri);

	PG_RETURN_POINTER((t_uri *) cstring_to_text(buffer));
}

PG_FUNCTION_INFO_V1(uri_out);

Datum
uri_out(PG_FUNCTION_ARGS)
{
	Datum		url = PG_GETARG_DATUM(0);
        
	PG_RETURN_CSTRING(TextDatumGetCString(url));
}

PG_FUNCTION_INFO_V1(uri_recv);
Datum
uri_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);


	BpChar	   *result;
	char	   *str;
	int         nbytes;

	str = pq_getmsgtext(buf, buf->len - buf->cursor, &nbytes);
	memcpy(result, str, nbytes);
	pfree(str);
	PG_RETURN_BPCHAR_P(result);
}

PG_FUNCTION_INFO_V1(uri_send);
Datum
uri_send(PG_FUNCTION_ARGS)
{
	char            *s = PG_GETARG_CHAR(0);
	StringInfoData buf;

	pq_begintypsend(&buf);
	pq_sendtext(&buf, s, strlen(s));
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}


PG_FUNCTION_INFO_V1(uri_get_scheme);
Datum
uri_get_scheme(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[8];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_scheme(uri, buffer, 8);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_get_auth);
Datum
uri_get_auth(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[BUFFER_SIZE];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_auth(uri, buffer, BUFFER_SIZE);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_get_host);
Datum
uri_get_host(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[BUFFER_SIZE];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_host(uri, buffer, BUFFER_SIZE);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_get_port);
Datum
uri_get_port(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[6];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_port(uri, buffer, 6);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_get_portnum);
Datum
uri_get_portnum(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
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
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[BUFFER_SIZE];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_path(uri, buffer, BUFFER_SIZE);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_get_query);
Datum
uri_get_query(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[BUFFER_SIZE];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_query(uri, buffer, BUFFER_SIZE);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_get_fragment);
Datum
uri_get_fragment(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[BUFFER_SIZE];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_fragment(uri, buffer, BUFFER_SIZE);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_is_absolute);
Datum
uri_is_absolute(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	URI	*uri;
	int	r;

	uri = uri_create_str(url, NULL);
	r = uri_absolute(uri);
        uri_destroy(uri);

	PG_RETURN_BOOL(r);

}

PG_FUNCTION_INFO_V1(uri_is_absolute_path);
Datum
uri_is_absolute_path(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
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
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	char	buffer[BUFFER_SIZE];
	URI	*uri;
	size_t	r;

	uri = uri_create_str(url, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url)));
	}
	r = uri_str(uri, buffer, BUFFER_SIZE);
        uri_destroy(uri);

	PG_RETURN_TEXT_P(cstring_to_text(buffer));

}

PG_FUNCTION_INFO_V1(uri_is_equal);
Datum
uri_is_equal(PG_FUNCTION_ARGS)
{
	Datum	url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	Datum	url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
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
	Datum	url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	Datum	url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
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
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));

        PG_RETURN_INT32(hash_any(url, sizeof(url)));
}

PG_FUNCTION_INFO_V1(uri_compare);
Datum
uri_compare(PG_FUNCTION_ARGS)
{
	Datum	url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	Datum	url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
	URI	*uri1;
	URI	*uri2;
	char    buffer1[BUFFER_SIZE];
	char    buffer2[BUFFER_SIZE];
	int	r;

	uri1 = uri_create_str(url1, NULL);
	if (!uri1)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse left URI '%s'", url1)));
	}

	uri2 = uri_create_str(url2, NULL);
	if (!uri2)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse right URI '%s'", url2)));
	}

	r = uri_str(uri1, buffer1, BUFFER_SIZE);
	r = uri_str(uri2, buffer2, BUFFER_SIZE);
        uri_destroy(uri1);
        uri_destroy(uri2);

	PG_RETURN_INT32(strcmp(buffer1, buffer2));

}

PG_FUNCTION_INFO_V1(uri_localpath_exists);
Datum
uri_localpath_exists(PG_FUNCTION_ARGS)
{
	Datum		url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char		localpath[MAXPGPATH];
	URI		*uri;
	bool		exists;
	struct stat	statbuf;
	size_t		r;

	uri = uri_create_str(url1, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url1)));
	}
	r = uri_path(uri, localpath, MAXPGPATH);
        uri_destroy(uri);

        /* Does the corresponding local file exists? */
        if (lstat(localpath, &statbuf) < 0)
        {
                if (errno != ENOENT)
			ereport(FATAL, (errmsg("could not stat file \"%s\": %s", localpath, strerror(errno))));
                exists = false;
        }
        else
                exists = true;

	PG_RETURN_BOOL(exists);

}

/*
 * Function tool used to search a string inside an
 * other one. It returns the position of the first
 * occurence or -1 when the string is not found
 */
int
search_str(char src[], char search[])
{
	int i, j, first;
	i = 0, j = 0;

	while (src[i] != '\0') {

		while (src[i] != search[0] && src[i] != '\0')
			i++;

		if (src[i] == '\0')
			return (-1);

		first= i;

		while (src[i] == search[j] && src[i] != '\0' && search[j] != '\0') {
			i++;
			j++;
		}

		if (search[j] == '\0')
			return (first);
		if (src[i] == '\0')
			return (-1);

		i = first + 1;
		j = 0;
	}
	return -1;
}

PG_FUNCTION_INFO_V1(uri_contains);
Datum
uri_contains(PG_FUNCTION_ARGS)
{
	Datum	url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	Datum	url2 = TextDatumGetCString(PG_GETARG_DATUM(1));
	URI	*uri1;
	URI	*uri2;
	char    buffer1[BUFFER_SIZE];
	char    buffer2[BUFFER_SIZE];
	int	r;

	uri1 = uri_create_str(url1, NULL);
	if (!uri1)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse left URI '%s'", url1)));
	}

	uri2 = uri_create_str(url2, NULL);
	if (!uri2)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse right URI '%s'", url2)));
	}

	r = uri_str(uri1, buffer1, BUFFER_SIZE);
	r = uri_str(uri2, buffer2, BUFFER_SIZE);
	uri_destroy(uri1);
	uri_destroy(uri2);

	if (search_str(buffer1, buffer2) >= 0)
		PG_RETURN_BOOL(true);

	PG_RETURN_BOOL(false);
}

PG_FUNCTION_INFO_V1(uri_contained);
Datum
uri_contained(PG_FUNCTION_ARGS)
{
	PG_RETURN_DATUM(DirectFunctionCall2( uri_contains, PG_GETARG_DATUM(1), PG_GETARG_DATUM(0) ));
}

PG_FUNCTION_INFO_V1(uri_rebase);
Datum
uri_rebase(PG_FUNCTION_ARGS)
{
	Datum	url = TextDatumGetCString(PG_GETARG_DATUM(0));
	Datum	base = TextDatumGetCString(PG_GETARG_DATUM(1));
	char    buffer[BUFFER_SIZE];
	URI     *h_uri;
	URI     *b_uri;
	size_t  r;

	b_uri = uri_create_str(base, NULL);
	if (!b_uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", base)));
	}
	h_uri = uri_create_str(url, b_uri);
	if (!h_uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to rebase URI '%s' with base '%s'", url, base)));
	}
	r = uri_str(h_uri, buffer, BUFFER_SIZE);
        uri_destroy(h_uri);
        uri_destroy(b_uri);

	PG_RETURN_POINTER((t_uri *) cstring_to_text(buffer));
}

PG_FUNCTION_INFO_V1(uri_localpath_size);
Datum
uri_localpath_size(PG_FUNCTION_ARGS)
{
	Datum		url1 = TextDatumGetCString(PG_GETARG_DATUM(0));
	char		localpath[MAXPGPATH];
	URI		*uri;
	bool		exists;
	struct stat	statbuf;
	size_t		r;

	uri = uri_create_str(url1, NULL);
	if (!uri)
	{
		ereport(ERROR,(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("failed to parse URI '%s'", url1)));
	}
	r = uri_path(uri, localpath, MAXPGPATH);
        uri_destroy(uri);

        /* Does the corresponding local file exists? */
        if (lstat(localpath, &statbuf) < 0)
        {
                if (errno != ENOENT)
			ereport(FATAL, (errmsg("could not stat file \"%s\": %s", localpath, strerror(errno))));
		PG_RETURN_NULL();
        }

	PG_RETURN_INT64(statbuf.st_size);

}


/*
 ereport(LOG, (errmsg("Some error msg: %s", err)));
*/
