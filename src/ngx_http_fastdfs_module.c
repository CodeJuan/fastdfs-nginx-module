#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.c"

#define OUT_BUFSIZE 256

static char *ngx_http_fastdfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_fastdfs_process_init(ngx_cycle_t *cycle);
static void ngx_http_fastdfs_process_exit(ngx_cycle_t *cycle);

/* Commands */
static ngx_command_t  ngx_http_fastdfs_commands[] = {
    { ngx_string("ngx_fastdfs_module"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_fastdfs_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_fastdfs_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

/* hook */
ngx_module_t  ngx_http_fastdfs_module = {
    NGX_MODULE_V1,
    &ngx_http_fastdfs_module_ctx,              /* module context */
    ngx_http_fastdfs_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_fastdfs_process_init,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_fastdfs_process_exit,             /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t fdfs_set_location(ngx_http_request_t *r, \
			struct fdfs_http_response *pResponse)
{
	ngx_table_elt_t  *cc;

	cc = r->headers_out.location;
	if (cc == NULL)
	{
		cc = ngx_list_push(&r->headers_out.headers);
		if (cc == NULL)
		{
			return NGX_ERROR;
        	}

		cc->hash = 1;
		cc->key.len = sizeof("Location") - 1;
		cc->key.data = (u_char *)"Location";
	}

	cc->value.len = pResponse->redirect_url_len;
	cc->value.data = (u_char *)pResponse->redirect_url;

	return NGX_OK;
}

static void fdfs_output_headers(void *arg, struct fdfs_http_response *pResponse)
{
	ngx_http_request_t *r;
	ngx_int_t rc;

	if (pResponse->header_outputed)
	{
		return;
	}

	pResponse->header_outputed = true;

	r = (ngx_http_request_t *)arg;
	r->headers_out.status = pResponse->status;

	if (pResponse->status != HTTP_OK)
	{
		if (pResponse->status == HTTP_MOVETEMP)
		{
			fdfs_set_location(r, pResponse);
		}
	}
	else
	{
		if (pResponse->content_type != NULL)
		{
		r->headers_out.content_type.len = strlen(pResponse->content_type);
		r->headers_out.content_type.data = pResponse->content_type;
		}

		r->headers_out.content_length_n = pResponse->content_length;
	}

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_send_header fail, return code=%d", rc);
		return;
	}
}

static int fdfs_send_reply_chunk(void *arg, const bool last_buf, \
		const char *buff, const int size)
{
	ngx_http_request_t *r;
	ngx_buf_t *b;
	ngx_chain_t out;
	ngx_int_t rc;
	u_char *new_buff;

	r = (ngx_http_request_t *)arg;

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_pcalloc fail");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	new_buff = ngx_pcalloc(r->pool, sizeof(u_char) * size);
	if (new_buff == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_pcalloc fail");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	out.buf = b;
	out.next = NULL;

	memcpy(new_buff, buff, size);

	b->pos = (u_char *)new_buff;
	b->last = (u_char *)new_buff + size;
	b->memory = 1;
	b->last_buf = last_buf;

	/*
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_output_filter, sent: %d", r->connection->sent);
	*/

	rc = ngx_http_output_filter(r, &out);
	if (rc == NGX_OK || rc == NGX_AGAIN)
	{
		return 0;
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_output_filter fail, return code: %d", rc);
		return rc;
	}
}

static ngx_int_t ngx_http_fastdfs_handler(ngx_http_request_t *r)
{
	struct fdfs_http_context context;
	ngx_int_t rc;
	size_t     root_length;  
	ngx_str_t  path;

	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
       		return NGX_HTTP_NOT_ALLOWED;
	}

	rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK && rc != NGX_AGAIN)
	{
		return rc;
	}

	if (ngx_http_map_uri_to_path(r, &path, &root_length, 0) == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"call ngx_http_map_uri_to_path fail");
        	return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	*(path.data + root_length) = '\0';
	*(r->unparsed_uri.data + r->unparsed_uri.len) = '\0';

	context.arg = r;
	context.header_only = r->header_only;
	context.url = r->unparsed_uri.data;
	context.document_root = path.data;
	context.output_headers = fdfs_output_headers;
	context.send_reply_chunk = fdfs_send_reply_chunk;
	context.server_port = ntohs(((struct sockaddr_in *)r->connection-> \
					local_sockaddr)->sin_port);
	
	return fdfs_http_request_handler(&context);
}

static char *ngx_http_fastdfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	int result;
	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, \
						ngx_http_core_module);

	fprintf(stderr, "ngx_http_fastdfs_set pid=%d\n", getpid());

	/* register hanlder */
	clcf->handler = ngx_http_fastdfs_handler;

	if ((result=fdfs_mod_init()) != 0)
	{
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_fastdfs_process_init(ngx_cycle_t *cycle)
{
    fprintf(stderr, "ngx_http_fastdfs_process_init pid=%d\n", getpid());
    // do some init here
    return NGX_OK;
}

static void ngx_http_fastdfs_process_exit(ngx_cycle_t *cycle)
{
    fprintf(stderr, "ngx_http_fastdfs_process_exit pid=%d\n", getpid());
    return;
}

