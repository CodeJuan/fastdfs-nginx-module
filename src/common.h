/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

#ifndef COMMON_H
#define COMMON_H

#include "tracker_types.h"

#ifndef HTTP_OK
#define HTTP_OK                    200
#endif

#ifndef HTTP_NOCONTENT
#define HTTP_NOCONTENT             204
#endif

#ifndef HTTP_MOVEPERM
#define HTTP_MOVEPERM              301
#endif

#ifndef HTTP_MOVETEMP
#define HTTP_MOVETEMP              302
#endif

#ifndef HTTP_NOTMODIFIED
#define HTTP_NOTMODIFIED           304
#endif

#ifndef HTTP_BADREQUEST
#define HTTP_BADREQUEST            400
#endif

#ifndef HTTP_NOTFOUND
#define HTTP_NOTFOUND              404
#endif

#ifndef HTTP_INTERNAL_SERVER_ERROR
#define HTTP_INTERNAL_SERVER_ERROR 500
#endif

#ifndef HTTP_SERVUNAVAIL
#define HTTP_SERVUNAVAIL           503
#endif

#ifndef FDFS_STORAGE_STORE_PATH_PREFIX_CHAR
#define FDFS_STORAGE_STORE_PATH_PREFIX_CHAR  'M'
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct fdfs_http_response;

typedef void (*FDFSOutputHeaders)(void *arg, struct fdfs_http_response *pResponse);
typedef int (*FDFSSendReplyChunk)(void *arg, const char *buff, const int size);

struct fdfs_http_response {
	int status;  //HTTP status
	int redirect_url_len;
	int64_t content_length;
	char *content_type;
	char redirect_url[256];
	bool header_outputed;   //if header output
};

struct fdfs_http_context {
	int server_port;
	bool header_only;
	const char *document_root;
	char *url;
	void *arg; //for callback
	FDFSOutputHeaders output_headers;
	FDFSSendReplyChunk send_reply_chunk;
};

struct fdfs_download_callback_args {
	struct fdfs_http_context *pContext;
	struct fdfs_http_response *pResponse;
};

/**
* init function
* params:
* return: 0 success, !=0 fail, return the error code
*/
int fdfs_mod_init();

/**
* http request handler
* params:
*	pContext the context
* return: http status code, HTTP_OK success, != HTTP_OK fail
*/
int fdfs_http_request_handler(struct fdfs_http_context *pContext);

#ifdef __cplusplus
}
#endif

#endif
