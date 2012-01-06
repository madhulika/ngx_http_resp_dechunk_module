
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* need to add the transfer_encoding field to ngx_http_upstream_headers_t structure */


typedef struct
{
    ngx_flag_t  enable;
}ngx_http_resp_dechunk_conf_t;

typedef enum dechunk_state_e dechunk_state_e;
enum dechunk_state_e
{
    DECHUNK_STATE_SIZE0 = 0,
    DECHUNK_STATE_SIZE1 = 1,
    DECHUNK_STATE_DATA  = 2,
    DECHUNK_STATE_SKIP_TRAILER = 3,
};

typedef struct
{
    ngx_flag_t excess_data;
    ngx_flag_t truncated;
    ngx_flag_t not_expecting_data;
}ngx_http_dechunk_bfc_flags_t;

typedef struct 
{
    size_t chunk_size;
    dechunk_state_e state;
    ngx_flag_t ncr;
    ngx_flag_t nlf;
    ngx_flag_t nspace;
    ngx_flag_t flush;   // flush not used anywhere
    ngx_flag_t done;    // default value to be decided
    ngx_chain_t *out;
    ngx_chain_t **last_out;
    ngx_http_dechunk_bfc_flags_t bfc_flags;
}ngx_http_dechunk_filter_ctx_t;


static ngx_int_t ngx_http_dechunk_filter_init(ngx_conf_t *cf);
static void *ngx_http_resp_dechunk_create_conf(ngx_conf_t *cf);
static char *ngx_http_resp_dechunk_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t  ngx_http_dechunk_filter_commands[] = {

    { ngx_string("dechunk"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_resp_dechunk_conf_t, enable),
      NULL},
    ngx_null_command
};

static ngx_http_module_t  ngx_http_dechunk_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_dechunk_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_resp_dechunk_create_conf,     /* create location configuration */
    ngx_http_resp_dechunk_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_resp_dechunk_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_dechunk_filter_module_ctx,      /* module context */
    ngx_http_dechunk_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};



static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static void *ngx_http_resp_dechunk_create_conf(ngx_conf_t *cf)
{
    ngx_http_resp_dechunk_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_resp_dechunk_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    return conf;
}
static char *ngx_http_resp_dechunk_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_resp_dechunk_conf_t *prev = parent;
    ngx_http_resp_dechunk_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;    
}

static ngx_int_t
ngx_http_resp_header_dechunk_filter(ngx_http_request_t *r)
{
    ngx_http_resp_dechunk_conf_t *conf;
    ngx_http_dechunk_filter_ctx_t *ctx;


    conf = ngx_http_get_module_loc_conf(r, ngx_http_resp_dechunk_filter_module);

    if (!conf->enable 
        || r->headers_out.status == NGX_HTTP_NOT_MODIFIED
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.content_length_n != -1
        || r->header_only
        || r->headers_out.transfer_encoding->value.len == 0
        || (r->method & NGX_HTTP_HEAD)
        || ngx_strncmp(r->headers_out.transfer_encoding->value.data, "chunked", sizeof("chunked")-1) != 0)
    {
       return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dechunk_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_resp_dechunk_filter_module);
    ctx->out = NULL;
    ctx->last_out = &ctx->out;


//    r->chunked = 0;
    r->headers_out.transfer_encoding->value.len = 0;
    r->headers_out.transfer_encoding->value.data = (u_char *) "";
    r->headers_out.transfer_encoding->hash = 0;
    r->headers_out.transfer_encoding = NULL;
    


    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 
                   "r#:%ui \"%V\" filter is used",
                   r->id, ctx->name);

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
parse_chunk(
            ngx_http_dechunk_filter_ctx_t *dechunk_ctx,
            ngx_http_request_t *r,
            ngx_buf_t *iob)
{

    while(iob->pos != iob->last && dechunk_ctx->done == 0) {
        u_char ch;
        size_t iob_len;

        /* sucking till CRLF, skip all leading spaces sent by broken
         * web server implementation like IIS
         */
        if(dechunk_ctx->nspace) {
            ch = *(iob->pos++);
            if(ch == ' ') {
                continue;
            } else if(ch == CR) {
                dechunk_ctx->nspace = 0;
                dechunk_ctx->ncr = 1;
                continue;
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "dechunk: received %uXd while CR or space(0x20) is expected", ch);
                return NGX_ERROR;
            }
        } 
        if(dechunk_ctx->ncr > dechunk_ctx->nlf) {
            ch = *(iob->pos++);
            if(ch != LF) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "dechunk received %uXd while LF is expected", ch);
                return NGX_ERROR;
            }

            dechunk_ctx->nlf++;
            switch(dechunk_ctx->state) {
            case DECHUNK_STATE_SIZE1:
                if(dechunk_ctx->chunk_size) {
                    dechunk_ctx->state = DECHUNK_STATE_DATA;
                    dechunk_ctx->ncr = dechunk_ctx->nlf = 0;
                } else {
                    dechunk_ctx->state = DECHUNK_STATE_SKIP_TRAILER;
                }
                continue;
            case DECHUNK_STATE_DATA:
                dechunk_ctx->state = DECHUNK_STATE_SIZE0;
                dechunk_ctx->ncr = dechunk_ctx->nlf = 0;
                continue;
            case DECHUNK_STATE_SKIP_TRAILER:
                if(dechunk_ctx->ncr == 2 && dechunk_ctx->nlf == 2)
                    dechunk_ctx->done = 1;
                continue;
            default:
                continue;
            }
        }

        switch(dechunk_ctx->state) {
        case DECHUNK_STATE_DATA:
            iob_len = ngx_buf_size(iob);
            if(dechunk_ctx->chunk_size == 0) {
                ch = *(iob->pos++);
                if(ch == ' ') {
                    dechunk_ctx->nspace = 1;
                    continue;
                } else if(ch == CR) {
                    dechunk_ctx->ncr = 1;
                    continue;
                } else {
                          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                " dechunk: received %uXd while expecting CR at the end of chunk-data", ch);
                    return NGX_ERROR;
                }
            }

           ngx_chain_t    *cl;
           cl = ngx_alloc_chain_link(r->pool);
           if (cl == NULL) {
               return NGX_ERROR;
           }

           cl->next = NULL;
           *dechunk_ctx->last_out = cl;
           dechunk_ctx->last_out = &cl->next;
           
            if(iob_len > dechunk_ctx->chunk_size) {
                /* we can't completely consume iob
                 * clone it and then append the clone to dechunk_ctx->out
                 */
                cl->buf = ngx_create_temp_buf(r->pool, dechunk_ctx->chunk_size); 
                if (cl->buf == NULL)
                    return NGX_ERROR;
                cl->buf->last = ngx_cpymem(cl->buf->last, iob->pos, dechunk_ctx->chunk_size);
               
                /* consume part of the iob */
                iob->pos += dechunk_ctx->chunk_size;
                /* adjust the last of the clone */
                dechunk_ctx->chunk_size = 0;
                continue;
            } else {

                cl->buf = iob;
                cl->next = NULL;
                dechunk_ctx->chunk_size -= iob_len;
                return NGX_DONE;
            }
            //ngx_assert(0 && "never reach here");
        case DECHUNK_STATE_SIZE0:
            ch = *(iob->pos);
            if(ch == CR || ch == LF) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "dechunk: received CR or LF while chunk size is expected");
                return NGX_ERROR;
            } /* else, fall through */
            dechunk_ctx->state = DECHUNK_STATE_SIZE1;
        case DECHUNK_STATE_SIZE1:
            ch = *(iob->pos++);
            if(ch == ' ') {
                dechunk_ctx->nspace = 1;
                continue;
            } else if(ch == CR) {
                dechunk_ctx->ncr = 1;
                continue;
            }

            if (ch >= '0' && ch <= '9') {
                dechunk_ctx->chunk_size
                    = dechunk_ctx->chunk_size * 16 + (ch - '0');
                continue;
            }

            ch = (u_char) (ch | 0x20);

            if (ch >= 'a' && ch <= 'f') {
                dechunk_ctx->chunk_size
                    = dechunk_ctx->chunk_size * 16 + (ch - 'a' + 10);
                continue;
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "dechunk: received %uxd while parsing for chunk size", ch);
                return NGX_ERROR;
            }
        case DECHUNK_STATE_SKIP_TRAILER:
            ch = *(iob->pos++);
            if(ch == CR) {
                dechunk_ctx->ncr++;
            } else if(ch != LF) {
                dechunk_ctx->ncr = dechunk_ctx->nlf = 0;
            } else {
                /* ch == LF */
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "dechunk: received LF while expecting the chunk trailer or CR");
                return NGX_ERROR;
            }
            continue;
        }
    }
            
    return NGX_OK;
}

static ngx_int_t
ngx_http_dechunk_body_filter(
                        ngx_http_request_t *r,
                        ngx_chain_t *in)
{
    ngx_buf_t *eof = NULL;
    ngx_http_dechunk_filter_ctx_t *ctx;
    ngx_chain_t *cl;
    ngx_int_t rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_resp_dechunk_filter_module);
    if (ctx == NULL || (ctx->done == 1))
    {
        return ngx_http_next_body_filter(r, in);
    }
 //   r->chunked = 0;


    for( ; in; in = in->next) {
       ngx_int_t rc;

       rc = parse_chunk(ctx, r, in->buf);
       if(rc == NGX_ERROR) {
           return  NGX_ERROR;
        }
    }

    if(ctx->done == 1) {
         cl = ngx_alloc_chain_link(r->pool);
         if (cl == NULL) {
            return NGX_ERROR;
         }
         if(!eof) 
         {
             eof = ngx_calloc_buf(r->pool);
             if (eof == NULL)
             {
               return NGX_ERROR;
             }
             eof->memory = 1;
             eof->last_buf = 1;
             eof->pos = (u_char *) CRLF CRLF;
             eof->last = eof->pos + 4;
         }
         cl->buf = eof;
         cl->next = NULL;
         *ctx->last_out = cl;
         ctx->last_out = &cl->next;
         r->upstream->length = 0;
    }

    rc = ngx_http_next_body_filter(r, ctx->out);
    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    return rc;

}

static ngx_int_t
ngx_http_dechunk_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_resp_header_dechunk_filter;

     /* body filters */
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_dechunk_body_filter;

    return NGX_OK;
}


