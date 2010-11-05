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
	b->last_in_chain = last_buf;
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

static int fdfs_send_file(void *arg, const char *filename, \
		const int filename_len)
{
	ngx_http_request_t *r;
	ngx_http_core_loc_conf_t *ccf;
	ngx_buf_t *b;
	ngx_str_t ngx_filename;
	ngx_open_file_info_t of;
	ngx_chain_t out;
	ngx_uint_t level;
	ngx_int_t rc;

	r = (ngx_http_request_t *)arg;

	ccf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	ngx_filename.data = (u_char *)filename;
	ngx_filename.len = filename_len;

	ngx_memzero(&of, sizeof(ngx_open_file_info_t));

#if defined(nginx_version) && (nginx_version >= 8018)
	of.read_ahead = ccf->read_ahead;
#endif
	of.directio = ccf->directio;
	of.valid = ccf->open_file_cache_valid;
	of.min_uses = ccf->open_file_cache_min_uses;
	of.errors = ccf->open_file_cache_errors;
	of.events = ccf->open_file_cache_events;
	if (ngx_open_cached_file(ccf->open_file_cache, &ngx_filename, \
			&of, r->pool) != NGX_OK)
	{
		switch (of.err)
		{
			case 0:
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			case NGX_ENOENT:
			case NGX_ENOTDIR:
			case NGX_ENAMETOOLONG:
				level = NGX_LOG_ERR;
				rc = NGX_HTTP_NOT_FOUND;
				break;
			case NGX_EACCES:
				level = NGX_LOG_ERR;
				rc = NGX_HTTP_FORBIDDEN;
				break;
			default:
				level = NGX_LOG_CRIT;
				rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
				break;
		}

		if (rc != NGX_HTTP_NOT_FOUND || ccf->log_not_found)
		{
			ngx_log_error(level, r->connection->log, of.err, \
				"%s \"%s\" failed", of.failed, filename);
		}

		return rc;
	}

	if (!of.is_file)
	{
		ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno, \
			"\"%s\" is not a regular file", filename);
		return NGX_HTTP_NOT_FOUND;
	}

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_pcalloc fail");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
	if (b->file == NULL)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	out.buf = b;
	out.next = NULL;

        b->file_pos = 0;
	b->file_last = of.size;
	b->in_file = b->file_last > 0 ? 1 : 0;
	b->file->fd = of.fd;
	b->file->name.data = (u_char *)filename;
	b->file->name.len = filename_len;
	b->file->log = r->connection->log;
	b->file->directio = of.is_directio;

	b->last_in_chain = 1;
	b->last_buf = 1;

	rc = ngx_http_output_filter(r, &out);
	if (rc == NGX_OK || rc == NGX_AGAIN)
	{
		return NGX_HTTP_OK;
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_output_filter fail, return code: %d", rc);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
	context.send_file = fdfs_send_file;
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

