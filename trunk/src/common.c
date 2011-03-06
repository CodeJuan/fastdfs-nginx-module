/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "fdfs_define.h"
#include "logger.h"
#include "shared_func.h"
#include "fdfs_global.h"
#include "sockopt.h"
#include "http_func.h"
#include "fdfs_http_shared.h"
#include "fdfs_client.h"
#include "local_ip_func.h"
#include "common.h"

#define FDFS_MOD_REPONSE_MODE_PROXY	'P'
#define FDFS_MOD_REPONSE_MODE_REDIRECT	'R'

static int storage_server_port = FDFS_STORAGE_SERVER_DEF_PORT;
static int group_name_len = 0;
static bool url_have_group_name = false;
static char group_name[FDFS_GROUP_NAME_MAX_LEN + 1] = {0};
static char response_mode = FDFS_MOD_REPONSE_MODE_PROXY;
static FDFSHTTPParams g_http_params;
static int storage_sync_file_max_delay = 24 * 3600;

static int fdfs_get_params_from_tracker();

int fdfs_mod_init()
{
        IniContext iniContext;
	int result;
	char *pBasePath;
	char *pLogFilename;
	char *pReponseMode;
	char *pGroupName;
	char *pIfAliasPrefix;

	log_init();

	if ((result=iniLoadFromFile(FDFS_MOD_CONF_FILENAME, &iniContext)) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"load conf file \"%s\" fail, ret code: %d", \
			__LINE__, FDFS_MOD_CONF_FILENAME, result);
		return result;
	}

	do
	{
	pBasePath = iniGetStrValue(NULL, "base_path", &iniContext);
	if (pBasePath == NULL)
	{
		logError("file: "__FILE__", line: %d, " \
			"conf file \"%s\" must have item " \
			"\"base_path\"!", __LINE__, FDFS_MOD_CONF_FILENAME);
		result = ENOENT;
		break;
	}

	snprintf(g_fdfs_base_path, sizeof(g_fdfs_base_path), "%s", pBasePath);
	chopPath(g_fdfs_base_path);
	if (!fileExists(g_fdfs_base_path))
	{
		logError("file: "__FILE__", line: %d, " \
			"\"%s\" can't be accessed, error info: %s", \
			__LINE__, g_fdfs_base_path, strerror(errno));
		result = errno != 0 ? errno : ENOENT;
		break;
	}
	if (!isDir(g_fdfs_base_path))
	{
		logError("file: "__FILE__", line: %d, " \
			"\"%s\" is not a directory!", \
			__LINE__, g_fdfs_base_path);
		result = ENOTDIR;
		break;
	}

	g_fdfs_connect_timeout = iniGetIntValue(NULL, "connect_timeout", \
			&iniContext, DEFAULT_CONNECT_TIMEOUT);
	if (g_fdfs_connect_timeout <= 0)
	{
		g_fdfs_connect_timeout = DEFAULT_CONNECT_TIMEOUT;
	}

	g_fdfs_network_timeout = iniGetIntValue(NULL, "network_timeout", \
			&iniContext, DEFAULT_NETWORK_TIMEOUT);
	if (g_fdfs_network_timeout <= 0)
	{
		g_fdfs_network_timeout = DEFAULT_NETWORK_TIMEOUT;
	}

	load_log_level(&iniContext);

	pLogFilename = iniGetStrValue(NULL, "log_filename", &iniContext);
	if (pLogFilename != NULL && *pLogFilename != '\0')
	{
		if ((result=log_set_filename(pLogFilename)) != 0)
		{
			break;
		}
	}

	result = fdfs_load_tracker_group_ex(&g_tracker_group, \
			FDFS_MOD_CONF_FILENAME, &iniContext);
	if (result != 0)
	{
		break;
	}

	storage_server_port = iniGetIntValue(NULL, "storage_server_port", \
			&iniContext, FDFS_STORAGE_SERVER_DEF_PORT);

	url_have_group_name = iniGetBoolValue(NULL, "url_have_group_name", \
						&iniContext, false);
	pGroupName = iniGetStrValue(NULL, "group_name", &iniContext);
	if (pGroupName != NULL)
	{
		snprintf(group_name, sizeof(group_name), "%s", pGroupName);
	}

	group_name_len = strlen(group_name);
	if ((!url_have_group_name) && group_name_len == 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"you must set parameter: group_name!", __LINE__);
		result = ENOENT;
		break;
	}

	if ((result=fdfs_http_params_load(&iniContext, FDFS_MOD_CONF_FILENAME, \
		&g_http_params)) != 0)
	{
		break;
	}

	pReponseMode = iniGetStrValue(NULL, "response_mode", &iniContext);
	if (pReponseMode != NULL)
	{
		if (strcmp(pReponseMode, "redirect") == 0)
		{
			response_mode = FDFS_MOD_REPONSE_MODE_REDIRECT;
		}
	}

	pIfAliasPrefix = iniGetStrValue (NULL, "if_alias_prefix", &iniContext);
	if (pIfAliasPrefix == NULL)
	{
		*g_if_alias_prefix = '\0';
	}
	else
	{
		snprintf(g_if_alias_prefix, sizeof(g_if_alias_prefix),
			"%s", pIfAliasPrefix);
	}

	} while (false);

	iniFreeContext(&iniContext);
	if (result != 0)
	{
		return result;
	}

	load_local_host_ip_addrs();
	fdfs_get_params_from_tracker();
	
	logInfo("fastdfs apache / nginx module v1.04, " \
		"response_mode=%s, " \
		"base_path=%s, " \
		"connect_timeout=%d, "\
		"network_timeout=%d, "\
		"tracker_server_count=%d, " \
		"storage_server_port=%d, " \
		"group_name=%s, " \
		"if_alias_prefix=%s, " \
		"local_host_ip_count=%d, " \
		"need_find_content_type=%d, " \
		"default_content_type=%s, " \
		"anti_steal_token=%d, " \
		"token_ttl=%ds, " \
		"anti_steal_secret_key length=%d, "  \
		"token_check_fail content_type=%s, " \
		"token_check_fail buff length=%d, "  \
		"storage_sync_file_max_delay=%ds", \
		response_mode == FDFS_MOD_REPONSE_MODE_PROXY ? \
			"proxy" : "redirect", \
		g_fdfs_base_path, g_fdfs_connect_timeout, \
		g_fdfs_network_timeout, g_tracker_group.server_count, \
		storage_server_port, group_name, \
		g_if_alias_prefix, g_local_host_ip_count, \
		g_http_params.need_find_content_type, \
		g_http_params.default_content_type, \
		g_http_params.anti_steal_token, \
		g_http_params.token_ttl, \
		g_http_params.anti_steal_secret_key.length, \
		g_http_params.token_check_fail_content_type, \
		g_http_params.token_check_fail_buff.length, \
		storage_sync_file_max_delay);

	//print_local_host_ip_addrs();

	return 0;
}

#define OUTPUT_HEADERS(pContext, pResponse, http_status) \
	pResponse->status = http_status;  \
	pContext->output_headers(pContext->arg, pResponse);

int fdfs_download_callback(void *arg, const int64_t file_size, \
		const char *data, const int current_size)
{
	struct fdfs_download_callback_args *pCallbackArgs;

	pCallbackArgs = (struct fdfs_download_callback_args *)arg;

	if (!pCallbackArgs->pResponse->header_outputed)
	{
		pCallbackArgs->pResponse->content_length = file_size;
		OUTPUT_HEADERS(pCallbackArgs->pContext, \
			pCallbackArgs->pResponse, HTTP_OK)
	}

	pCallbackArgs->sent_bytes += current_size;
	return pCallbackArgs->pContext->send_reply_chunk( \
		pCallbackArgs->pContext->arg, \
		(pCallbackArgs->sent_bytes == file_size) ? 1 : 0, \
		data, current_size);
}

int fdfs_http_request_handler(struct fdfs_http_context *pContext)
{
#define HTTPD_MAX_PARAMS   32
	char *file_id_without_group;
	char *url;
	char file_id[128];
	char uri[256];
	int url_len;
	int uri_len;
	KeyValuePair params[HTTPD_MAX_PARAMS];
	int param_count;
	char *p;
	char *filename;
	char *true_filename;
	char full_filename[MAX_PATH_SIZE + 64];
	char content_type[64];
	char file_trunk_buff[FDFS_OUTPUT_CHUNK_SIZE];
	struct stat file_stat;
	off_t remain_bytes;
	int read_bytes;
	int filename_len;
	int full_filename_len;
	int fd;
	int result;
	int http_status;
	struct fdfs_http_response response;
	FDFSFileInfo file_info;
	bool bFileExists;

	memset(&response, 0, sizeof(response));
	response.status = HTTP_OK;

	//logInfo("url=%s", pContext->url);

	url_len = strlen(pContext->url);
	if (url_len < 16)
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
		return HTTP_BADREQUEST;
	}

	if (strncasecmp(pContext->url, "http://", 7) == 0)
	{
		p = strchr(pContext->url+7, '/');
		if (p == NULL)
		{
			OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
			return HTTP_BADREQUEST;
		}

		uri_len = url_len - (p - pContext->url);
		url = p;
	}
	else
	{
		uri_len = url_len;
		url = pContext->url;
	}

	if (uri_len + 1 >= (int)sizeof(uri))
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
		return HTTP_BADREQUEST;
	}

	if (*url != '/')
	{
		*uri = '/';
		memcpy(uri+1, url, uri_len+1);
		uri_len++;
	}
	else
	{
		memcpy(uri, url, uri_len+1);
	}

	param_count = http_parse_query(uri, params, HTTPD_MAX_PARAMS);
	if (url_have_group_name)
	{
		snprintf(file_id, sizeof(file_id), "%s", uri + 1);
		file_id_without_group = strchr(file_id, '/');
		if (file_id_without_group == NULL)
		{
			OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
			return HTTP_BADREQUEST;
		}
		file_id_without_group++;  //skip /
	}
	else
	{
		file_id_without_group = uri + 1; //skip /
		snprintf(file_id, sizeof(file_id), "%s/%s", \
			group_name, file_id_without_group);
	}

	if (strlen(file_id_without_group) < 22)
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
		return HTTP_BADREQUEST;
	}

	if (g_http_params.anti_steal_token)
	{
		char *token;
		char *ts;
		int timestamp;

		token = fdfs_http_get_parameter("token", params, param_count);
		ts = fdfs_http_get_parameter("ts", params, param_count);
		if (token == NULL || ts == NULL)
		{
			OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
			return HTTP_BADREQUEST;
		}

		timestamp = atoi(ts);
		if (fdfs_http_check_token(&g_http_params.anti_steal_secret_key,\
					file_id_without_group, timestamp, token, \
					g_http_params.token_ttl) != 0)
		{
			if (*(g_http_params.token_check_fail_content_type))
			{
				response.content_length = g_http_params.token_check_fail_buff.length;
				response.content_type = g_http_params.token_check_fail_content_type;
				OUTPUT_HEADERS(pContext, (&response), HTTP_OK)

				pContext->send_reply_chunk(pContext->arg, 1, \
					g_http_params.token_check_fail_buff.buff, 
					g_http_params.token_check_fail_buff.length);

				return HTTP_OK;
			}
			else
			{
				OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
				return HTTP_BADREQUEST;
			}
		}
	}

	filename = file_id_without_group;
	filename_len = strlen(filename);

	//logInfo("filename=%s", filename);

	if (filename_len <= FDFS_FILE_PATH_LEN)
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
		return HTTP_BADREQUEST;
	}

	if (*filename != FDFS_STORAGE_STORE_PATH_PREFIX_CHAR)
        { /* version < V1.12 */
		true_filename = filename;
        }
	else if (*(filename + 3) != '/')
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
		return HTTP_BADREQUEST;
	}
	else
	{
		filename_len -= 4;  //skip Mxx/
		true_filename = filename + 4;
	}
	
	if (fdfs_check_data_filename(true_filename, filename_len) != 0)
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
		return HTTP_BADREQUEST;
	}

	if ((result=fdfs_get_file_info_ex1(file_id, false, &file_info)) != 0)
	{
		if (result == ENOENT)
		{
			http_status = HTTP_NOTFOUND;
		}
		else
		{
			http_status = HTTP_INTERNAL_SERVER_ERROR;
		}

		OUTPUT_HEADERS(pContext, (&response), http_status)
		return http_status;
	}

	full_filename_len = snprintf(full_filename, sizeof(full_filename), \
			"%s/%s", pContext->document_root, filename);
	memset(&file_stat, 0, sizeof(file_stat));
	if (stat(full_filename, &file_stat) != 0)
	{
		bFileExists = false;
	}
	else
	{
		bFileExists = true;
	}

	response.attachment_filename = fdfs_http_get_parameter("filename", \
						params, param_count);
	if (!bFileExists)
	{
		char *redirect;

		if (is_local_host_ip(file_info.source_ip_addr) || \
		(file_info.create_timestamp > 0 && (time(NULL) - \
		file_info.create_timestamp > storage_sync_file_max_delay)))
		{
			logDebug("file: "__FILE__", line: %d, " \
				"file: %s not exists, " \
				"errno: %d, error info: %s", \
				__LINE__, full_filename, \
				errno, strerror(errno));

			OUTPUT_HEADERS(pContext, (&response), HTTP_NOTFOUND)
			return HTTP_NOTFOUND;
		}
		//logInfo("source ip addr: %s", file_info.source_ip_addr);

		redirect = fdfs_http_get_parameter("redirect", \
						params, param_count);
		if (redirect != NULL)
		{
			logWarning("file: "__FILE__", line: %d, " \
				"redirect again, url: %s", \
				__LINE__, url);

			OUTPUT_HEADERS(pContext, (&response), HTTP_BADREQUEST)
			return HTTP_BADREQUEST;
		}

		if (response_mode == FDFS_MOD_REPONSE_MODE_REDIRECT)
		{
			char *path_split_str;
			char port_part[16];
			char param_split_char;
			
			if (pContext->server_port == 80)
			{
				*port_part = '\0';
			}
			else
			{
				sprintf(port_part, ":%d", pContext->server_port);
			}

			if (param_count == 0)
			{
				param_split_char = '?';
			}
			else
			{
				param_split_char = '&';
			}

			if (*url != '/')
			{
				path_split_str = "/";
			}
			else
			{
				path_split_str = "";
			}
	
			response.redirect_url_len = snprintf( \
				response.redirect_url, \
				sizeof(response.redirect_url), \
				"http://%s%s%s%s%c%s", \
				file_info.source_ip_addr, port_part, \
				path_split_str, url, \
				param_split_char, "redirect=1");

			logDebug("file: "__FILE__", line: %d, " \
				"redirect to %s", \
				__LINE__, response.redirect_url);

			OUTPUT_HEADERS(pContext, (&response), HTTP_MOVETEMP)
			return HTTP_MOVETEMP;
		}
		else if (pContext->proxy_handler != NULL)
		{
			return pContext->proxy_handler(pContext->arg, \
					file_info.source_ip_addr);
		}
	}

	if (g_http_params.need_find_content_type)
	{
	if (fdfs_http_get_content_type_by_extname(&g_http_params, \
		true_filename, content_type, sizeof(content_type)) != 0)
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_SERVUNAVAIL)
		return HTTP_SERVUNAVAIL;
	}
	response.content_type = content_type;
	}

	if (pContext->header_only)
	{
		response.content_length = file_info.file_size;
		OUTPUT_HEADERS(pContext, (&response), HTTP_OK)

		return HTTP_OK;
	}

	if (!bFileExists)
	{
		TrackerServerInfo storage_server;
		struct fdfs_download_callback_args callback_args;
		int64_t file_size;

		strcpy(storage_server.ip_addr, file_info.source_ip_addr);
		storage_server.port = storage_server_port;
		storage_server.sock = -1;

		callback_args.pContext = pContext;
		callback_args.pResponse = &response;
		callback_args.sent_bytes = 0;

		result = storage_download_file_ex1(NULL, \
                	&storage_server, file_id, \
                	0, 0, fdfs_download_callback, \
			&callback_args, &file_size);

		logDebug("file: "__FILE__", line: %d, " \
			"storage_download_file_ex1 return code: %d, " \
			"file id: %s", __LINE__, result, file_id);

		if (result == 0)
		{
			http_status = HTTP_OK;
		}
		if (result == ENOENT)
		{
			http_status = HTTP_NOTFOUND;
		}
		else
		{
			http_status = HTTP_INTERNAL_SERVER_ERROR;
		}

		OUTPUT_HEADERS(pContext, (&response), http_status)
		return http_status;
	}

	response.content_length = file_stat.st_size;
	if (pContext->send_file != NULL)
	{
		OUTPUT_HEADERS(pContext, (&response), HTTP_OK)
		return pContext->send_file(pContext->arg, full_filename, \
				full_filename_len);
	}

	fd = open(full_filename, O_RDONLY);
	if (fd < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"open file %s fail, " \
			"errno: %d, error info: %s", __LINE__, \
			full_filename, errno, strerror(errno));
		OUTPUT_HEADERS(pContext, (&response), HTTP_SERVUNAVAIL)
		return HTTP_SERVUNAVAIL;
	}

	OUTPUT_HEADERS(pContext, (&response), HTTP_OK)

	remain_bytes = file_stat.st_size;
	while (remain_bytes > 0)
	{
		read_bytes = remain_bytes <= FDFS_OUTPUT_CHUNK_SIZE ? \
			     remain_bytes : FDFS_OUTPUT_CHUNK_SIZE;
		if (read(fd, file_trunk_buff, read_bytes) != read_bytes)
		{
			close(fd);
			logError("file: "__FILE__", line: %d, " \
				"read from file %s fail, " \
				"errno: %d, error info: %s", __LINE__, \
				full_filename, errno, strerror(errno));
			return HTTP_SERVUNAVAIL;
		}

		remain_bytes -= read_bytes;
		if (pContext->send_reply_chunk(pContext->arg, \
			(remain_bytes == 0) ? 1: 0, file_trunk_buff, \
			read_bytes) != 0)
		{
			close(fd);
			return HTTP_SERVUNAVAIL;
		}
	}

	close(fd);
	return HTTP_OK;
}

static int fdfs_get_params_from_tracker()
{
        IniContext iniContext;
	int result;
	bool continue_flag;

	continue_flag = false;
	if ((result=fdfs_get_ini_context_from_tracker(&g_tracker_group, \
		&iniContext, &continue_flag, false, NULL)) != 0)
        {
                return result;
        }

	storage_sync_file_max_delay = iniGetIntValue(NULL, \
                        "storage_sync_file_max_delay", \
                        &iniContext, 24 * 3600);

        iniFreeContext(&iniContext);

        return 0;
}
