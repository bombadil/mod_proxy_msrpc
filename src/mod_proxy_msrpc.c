/**************************************************************************
 *  Copyright (C) 2013 Astaro GmbH & Co. KG  -- a Sophos company
 *  Astaro GmbH & Co. KG licenses this file to You under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  Author: Micha Lenk <micha@lenk.info>  --  2013-03-05
 *
 ***************************************************************************/

/* Tunnel Microsoft's RPC_IN_DATA and RPC_OUT_DATA methods through to the server
 *
 * The source code of this module is based heavily on the source code of the
 * mod_proxy_http and the mod_proxy_connect modules.
 */

#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>
#include <http_config.h>
#include <mod_proxy.h>
#include <ap_socache.h>
#include <util_mutex.h>
#include <assert.h>
#include <errno.h>
#include "msrpc_pdu_parser.h"
#include "msrpc_sync.h"


#define CONN_BLKSZ AP_IOBUFSIZE
#define MSRPC_INITIAL_PDU_BUFLEN MSRPC_PDU_MAXLENGTH

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(proxy_msrpc);
#endif

module AP_MODULE_DECLARE_DATA proxy_msrpc_module;

/* methods used by Outlook Anywhere */
enum {
    MSRPC_M_DATA_IN = 0,
    MSRPC_M_DATA_OUT,
    MSRPC_M_LAST
};

static const char *const proxy_msrpc_id = "proxy-msrpc";
static int proxy_msrpc_configured;
static int msrpc_methods[MSRPC_M_LAST];
static ap_socache_provider_t *msrpc_session_cache_provider = NULL;
static ap_socache_instance_t *msrpc_session_cache = NULL;
static apr_global_mutex_t *msrpc_session_cache_mutex = NULL;
static int msrpc_session_cache_expiry = 5000000;    // default: 5 sec

typedef enum {
    SESSION_INIT = 0,
    SESSION_TUNNEL,
    SESSION_BROKEN,
} msrpc_session_state_t;

static const char const *session_state_name[] = {
    "INIT",
    "TUNNEL",
    "BROKEN",
    NULL
};

typedef struct {
    msrpc_session_state_t state;
} msrpc_session_rec_t;

typedef enum {
    MSRPC_SERVER_TO_CLIENT,
    MSRPC_CLIENT_TO_SERVER
} proxy_msrpc_direction_t;

typedef struct {
    int enabled:1;
    int enabled_set:1;
    apr_array_header_t *user_agents;
} proxy_msrpc_conf_t;

typedef struct {
    apr_int64_t body_length;
    apr_bucket_brigade *client_bb;
    apr_bucket_brigade *server_bb;
    char initial_pdu[MSRPC_INITIAL_PDU_BUFLEN];
    apr_off_t initial_pdu_offset;
    char outlook_session[37];
    int initialized;
} proxy_msrpc_request_data_t;

typedef struct _msrpc_backend {
    const char *proxy_function;
    proxy_conn_rec *conn;
    server_rec *server;
} msrpc_backend_t;

static
int proxy_msrpc_precfg(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptmp)
{
    apr_status_t rv = ap_mutex_register(pconf, proxy_msrpc_id,
                                        NULL, APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog,
                      "failed to register %s mutex", proxy_msrpc_id);
        return 500; /* An HTTP status would be a misnomer! */
    }
    msrpc_session_cache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                                      AP_SOCACHE_DEFAULT_PROVIDER,
                                                      AP_SOCACHE_PROVIDER_VERSION);
    proxy_msrpc_configured = 0;
    return OK;
}

static apr_status_t msrpc_session_cache_remove_lock(void *data)
{
    if (msrpc_session_cache_mutex) {
        apr_global_mutex_destroy(msrpc_session_cache_mutex);
        msrpc_session_cache_mutex = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t msrpc_session_cache_destroy(void *data)
{
    if (msrpc_session_cache) {
        msrpc_session_cache_provider->destroy(msrpc_session_cache, (server_rec *)data);
        msrpc_session_cache = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t proxy_msrpc_register_outlook_session(request_rec *r, proxy_msrpc_request_data_t *rdata)
{
    const char *cookie = rdata->outlook_session;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "%s: trying to register outlook session %s in state '%s'",
                  r->method, cookie, session_state_name[0]);

    /* OK, we're on.  Grab mutex to do our business */
    apr_status_t rv = apr_global_mutex_lock(msrpc_session_cache_mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: Failed to lock outlook session cache %s",
                      r->method, cookie);
        return rv;
    }

    msrpc_session_rec_t val;
    unsigned int vallen = sizeof(val);
    rv = msrpc_session_cache_provider->retrieve(msrpc_session_cache, r->server,
                                                (unsigned char *)cookie, strlen(cookie),
                                                (unsigned char *)&val, &vallen, r->pool);
    if (rv == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "%s: There is already a registered Outlook Session %s in cache, it is in state '%s'",
                      r->method, cookie, session_state_name[val.state]);
        rv = APR_FROM_OS_ERROR(EPROTO);
    } else {
        val.state = SESSION_INIT;
        apr_time_t expiry = apr_time_now() + msrpc_session_cache_expiry;
        rv = msrpc_session_cache_provider->store(msrpc_session_cache, r->server,
                                                 (unsigned char*)cookie, strlen(cookie),
                                                 expiry, (unsigned char*)&val, sizeof(val), r->pool);
    }

    /* We're done with the mutex */
    apr_status_t mutex_rv = apr_global_mutex_unlock(msrpc_session_cache_mutex);
    if (mutex_rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, mutex_rv, r,
                      "%s: Failed to release mutex!", r->method);
        return mutex_rv;
    }

    if (rv == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "%s: Successfully registered outlook session %s in state '%s'",
                      r->method, cookie, session_state_name[SESSION_INIT]);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: Failed to register Outlook Session %s in cache",
                      r->method, cookie);
    }

    return rv;
}

static apr_status_t proxy_msrpc_validate_outlook_session(request_rec *r, proxy_msrpc_request_data_t *rdata, msrpc_session_state_t newstate)
{
    uuid_t *vc_cookie = NULL;
    const char *error = NULL;
    const char *cookie = NULL;
    apr_status_t rv = msrpc_rts_get_virtual_channel_cookie(rdata->initial_pdu, &vc_cookie, &error);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                      "%s: Failed to validate Outlook Session: Cannot decode virtual channel cookie: %s",
                      r->method, error);
        return rv;
    }
    uuid_unparse(*vc_cookie, rdata->outlook_session);
    cookie = rdata->outlook_session;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "%s: trying to update Outlook Session %s to state '%s'",
                  r->method, cookie, session_state_name[newstate]);

    /* OK, we're on.  Grab mutex to do our business */
    rv = apr_global_mutex_lock(msrpc_session_cache_mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: Failed to lock outlook session cache %s",
                      r->method, cookie);
        return rv;
    }

    msrpc_session_rec_t val;
    unsigned int vallen = sizeof(val);
    rv = msrpc_session_cache_provider->retrieve(msrpc_session_cache, r->server,
                                                (unsigned char *)cookie, strlen(cookie),
                                                (unsigned char *)&val, &vallen, r->pool);
    if (rv == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: Outlook Session %s found in cache",
                      r->method, cookie);
        if (val.state == SESSION_INIT) {
            val.state = newstate;
            apr_time_t expiry = apr_time_now() + msrpc_session_cache_expiry;
            rv = msrpc_session_cache_provider->store(msrpc_session_cache, r->server,
                                                     (unsigned char*)cookie, strlen(cookie),
                                                     expiry, (unsigned char*)&val, sizeof(val), r->pool);
            if (rv == APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "%s: Outlook Session %s updated to state %s'",
                                  r->method, cookie, session_state_name[newstate]);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                              "%s: Failed to update Outlook Session %s in cache",
                              r->method, cookie);
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "%s: The registered Outlook Session %s is in unexpected state '%s'",
                          r->method, cookie, session_state_name[val.state]);
            rv = APR_FROM_OS_ERROR(EPROTO);
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: There is no registered Outlook Session %s in cache",
                      r->method, cookie);
    }

    /* We're done with the mutex */
    apr_status_t mutex_rv = apr_global_mutex_unlock(msrpc_session_cache_mutex);
    if (mutex_rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, mutex_rv, r,
                      "%s: Failed to release mutex!", r->method);
        return mutex_rv;
    }

    return rv;
}

static apr_status_t proxy_msrpc_check_outlook_session_state(request_rec *r, proxy_msrpc_request_data_t *rdata, msrpc_session_state_t expected_state)
{
    if (!rdata->outlook_session[0]) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Outlook Session cookie missing");
        return APR_FROM_OS_ERROR(EPROTO);
    }
    const char *session = rdata->outlook_session;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "%s: Checking whether Outlook Session %s is in state '%s'",
                  r->method, session, session_state_name[expected_state]);

     /* OK, we're on.  Grab mutex to do our business */
    apr_status_t rv = apr_global_mutex_lock(msrpc_session_cache_mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: Failed to lock cache for outlook session %s",
                      r->method, session);
        return rv;
    }

    msrpc_session_rec_t val;
    unsigned int vallen = sizeof(val);
    rv = msrpc_session_cache_provider->retrieve(msrpc_session_cache, r->server,
                                                (unsigned char *)session, strlen(session),
                                                (unsigned char *)&val, &vallen, r->pool);
    /* We're done with the mutex */
    apr_status_t mutex_rv = apr_global_mutex_unlock(msrpc_session_cache_mutex);
    if (mutex_rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, mutex_rv, r,
                      "%s: Failed to release mutex!", r->method);
        return mutex_rv;
    }

    /* evaluate the result of the cache retrieval */
    if (rv == APR_SUCCESS) {
        if (val.state == expected_state) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "%s: Outlook Session %s is in expected state '%s'",
                          r->method, session, session_state_name[val.state]);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "%s: The registered Outlook Session %s is in unexpected state '%s'",
                          r->method, session, session_state_name[val.state]);
            rv = APR_FROM_OS_ERROR(EPROTO);
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: Failed to retrieve Outlook Session %s from cache",
                      r->method, session);
    }
    return rv;
}

static
int proxy_msrpc_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                     server_rec *s)
{
    if (!proxy_msrpc_configured) {
        /* don't waste the overhead of initialization and creating mutex */
        return OK;
    }

    if (msrpc_session_cache_provider == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, plog,
                      "Please select a socache provider with OutlookAnywhereSOCache "
                      "(no default found on this platform). Maybe you need to "
                      "load mod_socache_shmcb or another socache module first");
        return 500; /* An HTTP status would be a misnomer! */
    }

    /* create a mutex for the session cache */
    apr_status_t rv = ap_global_mutex_create(&msrpc_session_cache_mutex, NULL,
                                             proxy_msrpc_id, NULL, s, p, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog,
                      "failed to create %s mutex", proxy_msrpc_id);
        return 500; /* An HTTP status would be a misnomer! */
    }
    apr_pool_cleanup_register(p, NULL, msrpc_session_cache_remove_lock, apr_pool_cleanup_null);

    /* create the session cache */
    const char *errmsg = msrpc_session_cache_provider->create(&msrpc_session_cache, NULL, ptemp, p);
    if (errmsg) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, "%s", errmsg);
        return 500; /* An HTTP status would be a misnomer! */
    }

    static struct ap_socache_hints msrpc_session_cache_hints = { 40, sizeof(msrpc_session_rec_t), 0 };
    msrpc_session_cache_hints.expiry_interval = msrpc_session_cache_expiry;
    rv = msrpc_session_cache_provider->init(msrpc_session_cache, proxy_msrpc_id,
                                            &msrpc_session_cache_hints, s, p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog,
                      "failed to initialise %s cache", proxy_msrpc_id);
        return 500; /* An HTTP status would be a misnomer! */
    }
    apr_pool_cleanup_register(p, (void*)s, msrpc_session_cache_destroy, apr_pool_cleanup_null);

    /* Register used HTTP methods */
    msrpc_methods[MSRPC_M_DATA_IN] = ap_method_register(p, "RPC_IN_DATA");
    msrpc_methods[MSRPC_M_DATA_OUT] = ap_method_register(p, "RPC_OUT_DATA");

    return OK;
}

static void proxy_msrpc_child_init(apr_pool_t *p, server_rec *s)
{
    if (!proxy_msrpc_configured) {
        return;       /* don't waste the overhead of creating mutex & cache */
    }

    const char *lock = apr_global_mutex_lockfile(msrpc_session_cache_mutex);
    apr_status_t rv = apr_global_mutex_child_init(&msrpc_session_cache_mutex, lock, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "failed to initialise mutex in child_init");
    }
}

/* The function proxy_msrpc_process_data() is currently limited to
 * simple tunneling of the binary data (in blocks of CONN_BLKSZ) from
 * client to server and vice versa. */
/* TODO: Add length validation of Outlook Anywhere (RPC over HTTP) PDUs
 * so that we don't end up accidentally tunneling real HTTP traffic. */
static
apr_status_t proxy_msrpc_process_data(request_rec *r, conn_rec *c_i, conn_rec *c_o,
                                      apr_bucket_brigade *bb, proxy_msrpc_direction_t dir)
{
    apr_status_t rv;
    apr_off_t len;
    const char *name = (dir == MSRPC_SERVER_TO_CLIENT) ? "server" : "client";

    do {
        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(c_i->input_filters, bb, AP_MODE_READBYTES,
                            APR_NONBLOCK_READ, CONN_BLKSZ);
        if (rv == APR_SUCCESS) {
            if (c_o->aborted)
                return APR_EPIPE;
            if (APR_BRIGADE_EMPTY(bb))
                break;
            len = -1;
            apr_brigade_length(bb, 0, &len);
            if (dir == MSRPC_SERVER_TO_CLIENT)
                r->bytes_sent += len;
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "read %" APR_OFF_T_FMT
                          " bytes from %s", len, name);
            rv = ap_pass_brigade(c_o->output_filters, bb);
            if (rv == APR_SUCCESS) {
                ap_fflush(c_o->output_filters, bb);
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "error on %s - ap_pass_brigade",
                              name);
            }
        } else if (!APR_STATUS_IS_EAGAIN(rv)) {
            if (APR_STATUS_IS_ECONNRESET(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                              "connection reset by %s", name);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                              "error on %s - ap_get_brigade", name);
            }
        }
    } while (rv == APR_SUCCESS);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        rv = APR_SUCCESS;
    }
    return rv;
}

static
int proxy_msrpc_pass_brigade(apr_bucket_alloc_t *bucket_alloc, request_rec *r,
                             proxy_conn_rec *p_conn, conn_rec *origin,
                             apr_bucket_brigade *bb, int flush)
{
    apr_status_t status;
    apr_off_t transferred;

    if (flush) {
        apr_bucket *e = apr_bucket_flush_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    apr_brigade_length(bb, 0, &transferred);
    if (transferred != -1)
        p_conn->worker->s->transferred += transferred;
    status = ap_pass_brigade(origin->output_filters, bb);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "pass request body failed to %pI (%s)",
                      p_conn->addr, p_conn->hostname);
        if (origin->aborted) {
            const char *ssl_note;

            if (((ssl_note = apr_table_get(origin->notes, "SSL_connect_rv"))
                != NULL) && (strcmp(ssl_note, "err") == 0)) {
                return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                     "Error during SSL Handshake with"
                                     " remote server");
            }
            return APR_STATUS_IS_TIMEUP(status) ? HTTP_GATEWAY_TIME_OUT : HTTP_BAD_GATEWAY;
        }
        else {
            return HTTP_BAD_REQUEST;
        }
    }
    apr_brigade_cleanup(bb);
    return OK;
}

static int proxy_msrpc_send_request_headers(request_rec *r, char *url,
                                               apr_bucket_brigade *bb,
                                               proxy_conn_rec *p_conn,
                                               conn_rec *origin)
{
    apr_pool_t *p = r->pool;

    /* send method line */
    char *buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.1" CRLF, NULL);
    apr_bucket *b = apr_bucket_pool_create(buf, strlen(buf), p, bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    /* send request headers */
    const apr_array_header_t *headers_in_array = apr_table_elts(r->headers_in);
    const apr_table_entry_t *headers_in = (const apr_table_entry_t *)headers_in_array->elts;
    int i;
    for (i = 0; i < headers_in_array->nelts; i++) {
        if (!headers_in[i].key || !headers_in[i].val) {
            continue;
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                      "%s: Sending HTTP request header line [%s: %s]", r->method, headers_in[i].key, headers_in[i].val);

        buf = apr_pstrcat(p, headers_in[i].key, ": ", headers_in[i].val, CRLF, NULL);
        b = apr_bucket_pool_create(buf, strlen(buf), p, bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }

    /* add empty line at the end of the headers */
    b = apr_bucket_immortal_create(CRLF, 2, bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return proxy_msrpc_pass_brigade(bb->bucket_alloc, r, p_conn, origin, bb, 1);
}

static int proxy_msrpc_send_pdu(request_rec *r, char *pdu, apr_off_t pdu_buflen,
                                apr_bucket_brigade *bb, proxy_conn_rec *p_conn,
                                conn_rec *destination)
{
    apr_size_t pdu_length = pdu_buflen;
    apr_status_t rv = msrpc_pdu_get_length(pdu, &pdu_length);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "getting PDU length");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_bucket *b = apr_bucket_immortal_create(pdu, pdu_length, bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return proxy_msrpc_pass_brigade(bb->bucket_alloc, r, p_conn, destination, bb, 1);
}

/* Search thru the input filters and remove the reqtimeout one */
static void proxy_msrpc_remove_reqtimeout(ap_filter_t *next)
{
    ap_filter_t *reqtimeout = NULL;
    ap_filter_rec_t *filter;

    filter = ap_get_input_filter_handle("reqtimeout");
    if (!filter) {
        return;
    }

    while (next) {
        if (next->frec == filter) {
            reqtimeout = next;
            break;
        }
        next = next->next;
    }
    if (reqtimeout) {
        ap_remove_input_filter(reqtimeout);
    }
}

static
int proxy_msrpc_tunnel(apr_pool_t *p, request_rec *r,
                       proxy_msrpc_request_data_t *rdata, proxy_conn_rec *p_conn)
{
    conn_rec *c = r->connection;
    apr_socket_t *client_socket = ap_get_conn_socket(c);
    conn_rec *origin = p_conn->connection;
    apr_socket_t *origin_socket = ap_get_conn_socket(origin);
    apr_bucket_brigade *bb_server = rdata->server_bb;
    apr_bucket_brigade *bb_client = rdata->client_bb;

    assert(APR_BRIGADE_EMPTY(bb_server));
    assert(APR_BRIGADE_EMPTY(bb_client));

    /* All bytes received from server should be counted as response body */
    r->sent_bodyct = 1;
    r->bytes_sent = 0;

    /* setup polling for connection */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "%s: setting up poll()", r->method);

    apr_pollset_t *pollset;
    apr_status_t rv = apr_pollset_create(&pollset, 2, r->pool, 0);
    if (rv != APR_SUCCESS) {
        apr_socket_close(origin_socket);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: error apr_pollset_create()", r->method);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Add client side to the poll */
    apr_pollfd_t pollfd;
    pollfd.p = r->pool;
    pollfd.desc_type = APR_POLL_SOCKET;
    pollfd.reqevents = APR_POLLIN;
    pollfd.desc.s = client_socket;
    pollfd.client_data = NULL;
    apr_pollset_add(pollset, &pollfd);

    /* Add the server side to the poll */
    pollfd.desc.s = origin_socket;
    apr_pollset_add(pollset, &pollfd);

    /*
     * Handle Data Transfer
     * Handle two way transfer of data over the socket (this is a tunnel).
     */

    /* we are now acting as a tunnel - the input/output filter stacks should
     * not contain any non-connection filters.
     */
    r->output_filters = c->output_filters;
    r->proto_output_filters = c->output_filters;
    r->input_filters = c->input_filters;
    r->proto_input_filters = c->input_filters;

    /* check whether there are still unprocessed bytes available on the server socket
     * This is needed because of the switch of the reading mode from
     * AP_MODE_GETLINE when reading HTTP response headers to AP_MODE_READBYTES
     * when reading binary data. */
    rv = proxy_msrpc_process_data(r, origin, c, bb_client, MSRPC_SERVER_TO_CLIENT);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: error in proxy_msrpc_process_data on server socket",
                      r->method);
        apr_socket_close(client_socket);
        c->aborted = 1;
        c->keepalive = AP_CONN_CLOSE;
        return OK;
    }

    int client_error = 0;
    /* If this is a RPC_IN_DATA request, we expect the RPC_OUT_DATA request to
     * switch the Outlook Session to tunnel mode. This means for RPC_IN_DATA
     * requests we have to check the Outlook Session state, for RPC_OUT_DATA
     * we did this already before calling this function. */
    int check_session_state = (r->method_number == msrpc_methods[MSRPC_M_DATA_IN]) ? 1 : 0;
    while (1) { /* Infinite loop until error (one side closes the connection) */
        apr_int32_t pollcnt;
        const apr_pollfd_t *signalled;
        rv = apr_pollset_poll(pollset, -1, &pollcnt, &signalled);
        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_EINTR(rv)) {
                continue;
            }
            apr_socket_close(origin_socket);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: error apr_poll()", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: woke from poll(), i=%d", r->method, pollcnt);

        apr_int32_t pi;
        for (pi = 0; pi < pollcnt; pi++) {
            const apr_pollfd_t *cur = &signalled[pi];

            if (cur->desc.s == origin_socket) {
                apr_int16_t pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                                  "%s: server socket was readable", r->method);
                    if (!bb_client) {
                        bb_client = apr_brigade_create(p, c->bucket_alloc);
                    }
                    rv = proxy_msrpc_process_data(r, origin, c, bb_client,
                                                  MSRPC_SERVER_TO_CLIENT);
                }
                else if ((pollevent & APR_POLLERR) || (pollevent & APR_POLLHUP)) {
                         rv = APR_EPIPE;
                         ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                                       "%s: err/hup on server connection", r->method);
                }
                if (rv != APR_SUCCESS)
                    client_error = 1;
            }
            else if (cur->desc.s == client_socket) {
                apr_int16_t pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                                  "%s: client socket was readable", r->method);
                    if (check_session_state) {
                        /* verify that this Outlook Session is in tunnel mode */
                        rv = proxy_msrpc_check_outlook_session_state(r, rdata, SESSION_TUNNEL);
                        if (rv != APR_SUCCESS) {
                            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                                          "%s: received unexpected (bad session state) data from client, breaking poll loop",
                                          r->method);
                            break;
                        }
                        check_session_state = 0;
                    }
                    rv = proxy_msrpc_process_data(r, c, origin, bb_server,
                                                  MSRPC_CLIENT_TO_SERVER);
                }
            }
            else {
                rv = APR_EBADF;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%s: unknown socket in pollset", r->method);
            }

        }
        if (rv != APR_SUCCESS) {
            break;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "%s: finished with poll() - cleaning up", r->method);

    /*
     * Clean Up: Close the socket and clean up
     */

    if (client_error)
        apr_socket_close(client_socket);
    else
        ap_lingering_close(origin);

    c->aborted = 1;
    c->keepalive = AP_CONN_CLOSE;

    return OK;
}

static int proxy_msrpc_read_and_parse_initial_pdu(request_rec *r, proxy_msrpc_request_data_t *rdata)
{
    apr_pool_t *p = r->pool;
    conn_rec *c = r->connection;
    if (!rdata->client_bb) {
        rdata->client_bb = apr_brigade_create(p, c->bucket_alloc);
    }
    apr_status_t rv;
    apr_off_t needed_bytes = MSRPC_PDU_MINLENGTH;
    apr_off_t offset = 0;
    apr_bucket_brigade *unparsed_bb = NULL;
    do {
        rv = ap_get_brigade(c->input_filters, rdata->client_bb,
                                              AP_MODE_READBYTES, APR_BLOCK_READ, needed_bytes);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read request body - ap_get_brigade", r->method);
            return HTTP_BAD_REQUEST;
        }

        apr_size_t buf_length = sizeof(rdata->initial_pdu) - offset;
        rv = apr_brigade_flatten(rdata->client_bb, &rdata->initial_pdu[offset], &buf_length);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read request body - apr_brigade_flatten", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (buf_length <= 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "%s: failed to read request body - apr_brigade_flatten returned no bytes", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: got %ld bytes of request body from client", r->method, buf_length);

        /* drop the flattened data from the bucket brigade and
         * cleanup client_bb for preparing next ap_get_brigade() */
        apr_bucket *b = NULL;
        rv = apr_brigade_partition(rdata->client_bb, buf_length, &b);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read request body - apr_brigade_partition", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        unparsed_bb = apr_brigade_split(rdata->client_bb, b);
        rv = apr_brigade_cleanup(rdata->client_bb);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read request body - apr_brigade_cleanup", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        // do byte accounting for loop termination condition
        offset += buf_length;
        if (needed_bytes >= buf_length) {
            needed_bytes -= buf_length;
        } else {
            needed_bytes = 0;
        }
        rdata->initial_pdu_offset += buf_length;

        // sanity check
        if (needed_bytes > 0 && unparsed_bb && !APR_BRIGADE_EMPTY(unparsed_bb)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "%s: failed to read request body - unparsed_bb is not empty, "
                          "but still %lu bytes needed from request body", r->method, needed_bytes);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } while (needed_bytes > 0);

    apr_size_t buf_length = rdata->initial_pdu_offset;
    apr_size_t pdu_length = MSRPC_PDU_MINLENGTH;
    rv = msrpc_pdu_get_length(rdata->initial_pdu, &pdu_length);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: failed to read request body - msrpc_pdu_get_length", r->method);
        return HTTP_BAD_REQUEST;
    }
    if (pdu_length < 10) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "%s: failed to read request body - bad PDU length %lu", r->method, pdu_length);
        return HTTP_BAD_REQUEST;
    }
    if (pdu_length > sizeof(rdata->initial_pdu)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(EMSGSIZE), r,
                      "%s: failed to read request body - insufficient buffer for PDU length %lu", r->method, pdu_length);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (pdu_length > rdata->body_length) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(EPROTO), r,
                      "%s: failed to read request body - PDU length %lu is larger than HTTP request body length %ld",
                      r->method, pdu_length, rdata->body_length);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "%s: MSRPC PDU length: %lu (%lu already in buffer)", r->method, pdu_length, buf_length);

    if (pdu_length > buf_length) {
        assert(APR_BRIGADE_EMPTY(unparsed_bb));
        apr_size_t remaining_length = pdu_length - buf_length;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: trying to get %lu more bytes from request body", r->method, remaining_length);
        rv = ap_get_brigade(c->input_filters, rdata->client_bb,
                            AP_MODE_READBYTES, APR_BLOCK_READ, remaining_length);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read remaining request body - ap_get_brigade", r->method);
            return HTTP_BAD_REQUEST;
        }
        rv = apr_brigade_flatten(rdata->client_bb, rdata->initial_pdu + rdata->initial_pdu_offset, &remaining_length);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read remaining request body - apr_brigade_flatten", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        rdata->initial_pdu_offset += remaining_length;

        /* drop the flattened date from the bucket brigade and
         * cleanup client_bb for preparing next ap_get_brigade() */
        apr_bucket *b = NULL;
        rv = apr_brigade_partition(rdata->client_bb, remaining_length, &b);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read remaining request body - apr_brigade_partition", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        unparsed_bb = apr_brigade_split_ex(rdata->client_bb, b, unparsed_bb);
        rv = apr_brigade_cleanup(rdata->client_bb);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: failed to read remaining request body - apr_brigade_cleanup", r->method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    assert(rdata->initial_pdu_offset >= pdu_length);
    rdata->initial_pdu_offset = pdu_length; // excess bytes are still in the bucket brigade rdata->client_bb
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "%s: MSRPC PDU length: %lu (completely in buffer)", r->method, pdu_length);

    /* cleanup bucket brigades */
    rv = ap_save_brigade(c->input_filters, &rdata->client_bb, &unparsed_bb, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "%s: failed save trailing bytes - ap_save_brigade", r->method);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_brigade_destroy(unparsed_bb);

    const char *error = NULL;
    rv = msrpc_pdu_validate(rdata->initial_pdu, &error);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "%s: invalid MSRPC PDU from client, reason: %s", r->method, error);
        return HTTP_BAD_REQUEST;
    }

    /* decode virtual channel cookie */
    uuid_t *vc_cookie = NULL;
    rv = msrpc_rts_get_virtual_channel_cookie(rdata->initial_pdu, &vc_cookie, &error);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                      "%s: Failed to register Outlook Session: Cannot decode virtual channel cookie: %s",
                      r->method, error);
        return HTTP_BAD_REQUEST;
    }
    uuid_unparse(*vc_cookie, rdata->outlook_session);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "%s: got initial MSRPC pdu (%lu bytes) for Outlook Session %s",
                  r->method, rdata->initial_pdu_offset, rdata->outlook_session);

    rv = HTTP_INTERNAL_SERVER_ERROR;
    if (r->method_number == msrpc_methods[MSRPC_M_DATA_IN]) {
        rv = proxy_msrpc_register_outlook_session(r, rdata);
    } else if (r->method_number == msrpc_methods[MSRPC_M_DATA_OUT]) {
        rv = OK;
    }
    return rv;
}

static int proxy_msrpc_read_server_response(request_rec *r, proxy_conn_rec *backend, apr_bucket_brigade *bb)
{
    apr_status_t rv;
    char buf[HUGE_STRING_LEN];
    apr_size_t buf_len = HUGE_STRING_LEN;

    assert(APR_BRIGADE_EMPTY(bb));
    rv = ap_get_brigade(backend->connection->input_filters, bb,
                        AP_MODE_GETLINE, APR_BLOCK_READ, buf_len);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                      "%s: failed to read status line from server", r->method);
        return HTTP_BAD_GATEWAY;
    }
    rv = apr_brigade_flatten(bb, buf, &buf_len);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                      "%s: failed to flatten status line from server in buffer", r->method);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    // protect against overly large strings not fitting into buf
    if (buf_len >= HUGE_STRING_LEN) {
        buf_len = HUGE_STRING_LEN - 1;
    }
    buf[buf_len] = 0;

    // remove trailing CRLF
    char *eol = strpbrk(buf, CRLF);
    if (eol) {
        buf_len = eol - buf;
    }

    // check server response
    if (!apr_date_checkmask(buf, "HTTP/1.1 ###*")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "%s: bad response from server: [%.*s]", r->method, (int)buf_len, buf);
        return HTTP_BAD_GATEWAY;
    }

    int backend_status_code = (buf[9]  - '0') * 100 +
                              (buf[10] - '0') *  10 +
                              (buf[11] - '0');
    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                  "%s: Got HTTP response status line (status code: %d)",
                  r->method, backend_status_code);
    r->status = backend_status_code;
    r->status_line = apr_pstrndup(r->pool, buf, buf_len);

    apr_brigade_cleanup(bb);
    apr_table_clear(r->headers_out);
    int expecting_response_headers = 1;
    while (expecting_response_headers) {
        rv = ap_get_brigade(backend->connection->input_filters, bb,
                            AP_MODE_GETLINE, APR_BLOCK_READ, buf_len);
        if (APR_STATUS_IS_ECONNRESET(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "connection reset by peer");
            expecting_response_headers = 0;
        } else if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "failed to read header line from server");
            return HTTP_BAD_GATEWAY;
        }
        if (buf_len > 0) {
            buf_len = HUGE_STRING_LEN;
            rv = apr_brigade_flatten(bb, buf, &buf_len);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "failed to flatten header line from server in buffer");
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            // protect against overly large strings not fitting into buf
            if (buf_len >= HUGE_STRING_LEN) {
                buf_len = HUGE_STRING_LEN - 1;
            }
            buf[buf_len] = 0;

            /* remove CR or LF at end of line */
            char *eol = strpbrk(buf, CRLF);
            if (eol)
                *eol = 0;

            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                          "%s: Got HTTP response header line [%s]",
                          r->method, buf);
            char *value = strchr(buf, ':');
            if (value) {
                *value = 0;
                value++;
                while (apr_isspace(*value))
                    value++;            /* Skip to start of value   */
                apr_table_add(r->headers_out, buf, value);
            } else {
                expecting_response_headers = 0;
            }
            if (buf[0] == 0) {
                expecting_response_headers = 0;
            }
        }
        apr_brigade_cleanup(bb);
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                  "%s: Got all HTTP response headers from server", r->method);

    /* parse some important response headers */
    apr_int64_t body_length = 0;
    const char *header_value = apr_table_get(r->headers_out, "Content-Length");
    if (header_value) {
        body_length = apr_atoi64(header_value);
        if (errno != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(errno), r,
                          "%s: Failed to parse response body Content-Length: '%s'",
                          r->method, header_value);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (backend_status_code != HTTP_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "%s: server refused MSRPC request for %s: [%s]",
                      r->method, r->unparsed_uri, r->status_line);
    }

    /* forward response headers to client */
    apr_bucket *e = apr_bucket_flush_create(bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    rv = ap_pass_brigade(r->proto_output_filters, bb);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                      "%s: failed to forward server response headers to client", r->method);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "%s: Forwarded all HTTP response headers to client", r->method);

    /* if there is a response body, forward it to the client */
    if (body_length > 0) {
        /* correctly log the request body size in reverseproxy.log */
        r->sent_bodyct = 1;
        r->bytes_sent = body_length;
        /* simplistic read request body, if present */
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: HTTP response body size: %ld bytes",
                      r->method, body_length);
        assert(APR_BRIGADE_EMPTY(bb));
        rv = ap_get_brigade(backend->connection->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, body_length);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "%s: Failed to read response body from server",
                          r->method);
            return HTTP_BAD_GATEWAY;
        }
        r->clength = body_length;
        /* forward response body to the client */
        e = apr_bucket_flush_create(bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        rv = ap_pass_brigade(r->connection->output_filters, bb);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                          "failed to forward server response body to client");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: no HTTP response body", r->method);
    }

    apr_brigade_cleanup(bb);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "%s: Forwarded the HTTP response to client", r->method);
    return backend_status_code;
}

static apr_status_t proxy_msrpc_disconnect_backend(void *data) {
    conn_rec *c = (conn_rec *)data;
    if (c == NULL)
        return APR_SUCCESS;

    msrpc_backend_t *d = (msrpc_backend_t *)ap_get_module_config(c->conn_config, &proxy_msrpc_module);
    if (d == NULL)
        return APR_SUCCESS;

    ap_set_module_config(c->conn_config, &proxy_msrpc_module, NULL);
    d->conn->close = 1;
    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, d->server,
                  "%s: Client connection cleanup triggered release of backend connection 0x%pp back to pool",
                  d->proxy_function, d->conn);
    ap_proxy_release_connection(d->proxy_function, d->conn, d->server);
    return APR_SUCCESS;
}

static int proxy_msrpc_connect_backend(request_rec *r, const char *proxy_function, proxy_conn_rec **backendp,
                                       proxy_worker *worker, proxy_server_conf *conf,
                                       char **locurl, const char *proxyname, apr_port_t proxyport, int is_ssl) {
    msrpc_backend_t *d = (msrpc_backend_t *)ap_get_module_config(r->connection->conn_config, &proxy_msrpc_module);
    if (d && d->conn) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: re-using already established connection 0x%pp to backend: %s",
                      r->method, d->conn, d->conn->hostname);
        *backendp = d->conn;
        return OK;
    }

    /* create space for state information */
    proxy_conn_rec *backend = NULL;
    int status = ap_proxy_acquire_connection(proxy_function, &backend,
                                             worker, r->server);
    if (status != OK)
        return status;

    *backendp = backend;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "%s: acquired backend connection 0x%pp",
                  r->method, backend);

    backend->is_ssl = is_ssl;

    if (is_ssl) {
        ap_proxy_ssl_connection_cleanup(backend, r);
    }

    /* We want to avoid the backend connection being reused.
     * As a safe-guard, mark the backend to be closed after use. */
    backend->close = 1;

    /* Step One: Determine Who To Connect To */
    char server_portstr[32];
    apr_uri_t *uri = apr_palloc(r->pool, sizeof(*uri));
    status = ap_proxy_determine_connection(r->pool, r, conf, worker, backend,
                                           uri, locurl, proxyname,
                                           proxyport, server_portstr,
                                           sizeof(server_portstr));
    if (status != OK)
        goto cleanup;

    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(proxy_function, backend, worker, r->server)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "%s: failed to make connection to backend: %s",
                      proxy_function, backend->hostname);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Create conn_rec */
    if (!backend->connection) {
        status = ap_proxy_connection_create(proxy_function, backend,
                                            r->connection, r->server);
        if (status != OK)
            goto cleanup;

        /* We want to avoid the backend connection being reused.
         * As a safe-guard, mark the backend to be closed after use. */
        backend->connection->keepalive = AP_CONN_CLOSE;

        /*
         * On SSL connections set a note on the connection what CN is
         * requested, such that mod_ssl can check if it is requested to do
         * so.
         */
        if (is_ssl) {
            proxy_dir_conf *dconf;
            const char *ssl_hostname;

            /*
             * In the case of ProxyPreserveHost on use the hostname of
             * the request if present otherwise use the one from the
             * backend request URI.
             */
            dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
            if ((dconf->preserve_host != 0) && (r->hostname != NULL)) {
                ssl_hostname = r->hostname;
            }
            else {
                ssl_hostname = uri->hostname;
            }

            apr_table_set(backend->connection->notes, "proxy-request-hostname",
                          ssl_hostname);
        }
    }

    /* Step four: Register backend connection with client connection
     *            This ensures that the backend connection is closed too
     *            as soon as the client connection is closed */
    msrpc_backend_t *cleanup_data = apr_pcalloc(r->connection->pool, sizeof(msrpc_backend_t));
    cleanup_data->proxy_function = apr_pstrdup(r->connection->pool, r->method);
    cleanup_data->conn = backend;
    cleanup_data->server = r->server;
    apr_pool_cleanup_register(r->connection->pool, r->connection,
                              proxy_msrpc_disconnect_backend,
                              apr_pool_cleanup_null);
    ap_set_module_config(r->connection->conn_config, &proxy_msrpc_module, cleanup_data);

    return OK;

cleanup:
    if (backend) {
        backend->close = 1;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: backend connection 0x%pp setup failed, returning to pool",
                      r->method, backend);
        ap_proxy_release_connection(proxy_function, backend, r->server);
    }
    return status;
}

/* MSRPC handler */
static int proxy_msrpc_handler(request_rec *r, proxy_worker *worker,
                               proxy_server_conf *conf,
                               char *url, const char *proxyname,
                               apr_port_t proxyport)
{
    int status = HTTP_INTERNAL_SERVER_ERROR;
    proxy_conn_rec *backend = NULL;
    apr_bucket_brigade *server_bb = NULL;
    const char *proxy_function = "HTTP";
    int is_ssl = 0;
    apr_pool_t *p = r->pool;

    proxy_msrpc_conf_t *msrpc_conf;
    msrpc_conf = (proxy_msrpc_conf_t *)ap_get_module_config(r->server->module_config,
                                                      &proxy_msrpc_module);
    /* is this module enabled? */
    if (!proxy_msrpc_configured || (!msrpc_conf) || !msrpc_conf->enabled) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "declining because being disabled in config");
        return DECLINED;
    }

    /* does the method number match? */
    if ((r->method_number != msrpc_methods[MSRPC_M_DATA_IN]) &&
        (r->method_number != msrpc_methods[MSRPC_M_DATA_OUT])) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "declining due to bad method: %s", r->method);
        return DECLINED;
    }

    /* does the user agent match? */
    const char *request_user_agent = apr_table_get(r->headers_in, "User-Agent");
    if (!request_user_agent) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "declining due to missing User-Agent header");
        return DECLINED;
    } else {
        int found = 0;
        if (!msrpc_conf->user_agents) {
            /* if no user agent explicitly configured, check for the default user agent */
            if (!strcasecmp(request_user_agent, "MSRPC")) {
                found = 1;
            }
        } else {
            /* otherwise iterate through list of configured user agents */
            const char **configured_user_agent = (const char **)msrpc_conf->user_agents->elts;
            int i;
            for (i = 0; i < msrpc_conf->user_agents->nelts; i++) {
                if (!strcasecmp(request_user_agent, configured_user_agent[i])) {
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "declining due to bad User-Agent: %s", request_user_agent);
            return DECLINED;
        }
    }

    /* find the scheme */
    const char *u = strchr(url, ':');
    if (u == NULL || u[1] != '/' || u[2] != '/' || u[3] == '\0')
       return DECLINED;
    if ((u - url) > 14)
        return HTTP_BAD_REQUEST;
    char *scheme = apr_pstrndup(p, url, u - url);
    /* scheme is lowercase */
    ap_str_tolower(scheme);
    /* is it for us? */
    if (strcmp(scheme, "https") == 0) {
        if (!ap_proxy_ssl_enable(NULL)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "HTTPS: declining URL %s (mod_ssl not configured?)",
                          url);
            return DECLINED;
        }
        is_ssl = 1;
        proxy_function = "HTTPS";
    }
    else if (strcmp(scheme, "http") != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HTTP: declining URL %s",
                      url);
        return DECLINED; /* only interested in HTTP via proxy */
    }

    /* do we have a request body? */
    const char *request_content_length = apr_table_get(r->headers_in, "Content-Length");
    apr_int64_t request_body_length = 0;
    if (request_content_length) {
        request_body_length = apr_strtoi64(request_content_length, NULL, 10);
        if (errno != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, errno, r,
                          "%s: declining due to unparsable header Content-Length: %s",
                          r->method, request_content_length);
            return DECLINED;
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "%s: serving URL %s", r->method, url);

    /* connect to backend
     * this re-uses an already established backend connection from an
     * earlier MSRPC request on the same client connection */
    char *locurl = url;
    status = proxy_msrpc_connect_backend(r, proxy_function, &backend, worker, conf, &locurl, proxyname, proxyport, is_ssl);
    if (status != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "%s: proxy_msrpc_connect_backend() failed to %pI (%s)",
                      r->method, worker->cp->addr, worker->s->hostname);
        return status;
    }

    server_bb = apr_brigade_create(backend->connection->pool, backend->connection->bucket_alloc);
    if (request_body_length == 0) {
        /* forward initial HTTP request without MSRPC payload */
        status = proxy_msrpc_send_request_headers(r, locurl, server_bb,
                                                  backend, backend->connection);
        if (status != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "%s: proxy_msrpc_send_request_headers() failed to %pI (%s)",
                          r->method, worker->cp->addr, worker->s->hostname);
            goto cleanup;
        }
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "%s: HTTP request sent to %pI (%s), now waiting for a response",
                      r->method, worker->cp->addr, worker->s->hostname);

        status = proxy_msrpc_read_server_response(r, backend, server_bb);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: proxy_msrpc_read_server_response() returned status code %d",
                      r->method, status);
        if (status != HTTP_UNAUTHORIZED) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "%s: server %pI (%s) did not accept request without PDU (HTTP status code %d)",
                          r->method, worker->cp->addr, worker->s->hostname, status);
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: proxy_msrpc_handler finished for request without body", r->method);
        return OK;
    }

    /* store request body length for later use */
    proxy_msrpc_request_data_t *rdata = ap_get_module_config(r->request_config, &proxy_msrpc_module);

    /* If we hit this point and rdata is NOT null this means mod_proxy called the
     * handler for a different backend server and it failed. Because
     * proxy_msrpc_read_and_parse_initial_pdu consumes the input brigade we
     * must not call it again. Hence reuse rdata. */
    if (rdata == NULL) {
        rdata = apr_pcalloc(r->pool, sizeof(proxy_msrpc_request_data_t));
        rdata->server_bb = server_bb;
        rdata->body_length = request_body_length;
        ap_set_module_config(r->request_config, &proxy_msrpc_module, rdata);

        /* wait for enough data coming in to parse the first MSRPC PDU */
        status = proxy_msrpc_read_and_parse_initial_pdu(r, rdata);
        if (status != OK) {
            goto cleanup;
        }
        /* body length of RPC_OUT_DATA requests needs to match PDU length */
        if (r->method_number == msrpc_methods[MSRPC_M_DATA_OUT]) {
            if (rdata->body_length != rdata->initial_pdu_offset) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "MSRPC PDU length %llu of RPC_OUT_DATA request "
                              "does not match request body length %lld",
                              rdata->initial_pdu_offset, rdata->body_length);
                return HTTP_BAD_REQUEST;
            }
        }

        /* if we made it here, we succeeded to read the initial PDU from the client */
        rdata->initialized = 1;
    } else {
        if (!rdata->initialized) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "MSRPC initialization for this request failed, cannot complete connection set up");
            goto cleanup;
        }

        /* set the server bucket brigade to the one in use curretly */
        rdata->server_bb = server_bb;
    }

    apr_uri_t *uri = apr_palloc(p, sizeof(*uri));
    int retry = 0;
    while (retry < 2) {

        /* Step Four: Send HTTP request headers to the backend server */
        status = proxy_msrpc_send_request_headers(r, locurl, rdata->server_bb,
                                                  backend, backend->connection);
        if (status != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%s: proxy_msrpc_send_request_headers() failed to %pI (%s)",
                              r->method, worker->cp->addr, worker->s->hostname);
            goto cleanup;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "%s: request headers successfully sent to server %pI (%s)",
                      r->method, worker->cp->addr, worker->s->hostname);

        /* Step Five: Forward the first PDU to the backend server */
        status = proxy_msrpc_send_pdu(r, rdata->initial_pdu, rdata->initial_pdu_offset,
                                      rdata->server_bb, backend, backend->connection);
        if (status != OK) {
            if ((status == HTTP_SERVICE_UNAVAILABLE) && worker->s->ping_timeout_set) {
                backend->close = 1;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r,
                              "%s: ap_proxy_msrpc_request() failed to %pI (%s)",
                              r->method, worker->cp->addr, worker->s->hostname);
                retry++;
                continue;
            }
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%s: proxy_msrpc_send_pdu() failed to %pI (%s)",
                              r->method, worker->cp->addr, worker->s->hostname);
            break;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "%s: initial PDU successfully sent to server %pI (%s)",
                      r->method, worker->cp->addr, worker->s->hostname);

        /* synchronize with RPC_DATA_IN request */
        // TODO: Replace hard-coded path by something configuration depending
        char *sync_key = apr_pstrcat(r->pool, "/tmp/msrpc_tunnel_", rdata->outlook_session, ".sync", NULL);

        if (r->method_number == msrpc_methods[MSRPC_M_DATA_OUT]) {
            /* Wait for "HTTP/1.1 200 OK" message from server */
            // TODO: proxy_msrpc_read_server_response() should NOT send data to the client so we can
            //       return propper HTTP errors when backend server was ok and 'we' failed. See below
            //       for a use case.
            status = proxy_msrpc_read_server_response(r, backend, rdata->server_bb);
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "%s: proxy_msrpc_read_server_response() returned status code %d",
                          r->method, status);
            if (status != HTTP_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "%s: server %pI (%s) did not accept initial PDU (HTTP status code %d)",
                              r->method, worker->cp->addr, worker->s->hostname, status);

                /* mark tunnel mode as failed */
                proxy_msrpc_validate_outlook_session(r, rdata, SESSION_BROKEN);
                int sync_rv = msrpc_sync_ready(sync_key, SESSION_BROKEN);
                if (sync_rv != 0) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(errno), r,
                                  "%s: Failed to sync broken Outlook Session %s: %d",
                                  r->method, rdata->outlook_session, sync_rv);
                }
                /* Do not 'return' here as we have to clean up the broken backend connection
                   with the 'cleanup' label. */
                break;
            }
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "%s: server %pI (%s) acknowledged the tunnel",
                          r->method, worker->cp->addr, worker->s->hostname);
            /* Switch to tunnel mode */
            proxy_msrpc_validate_outlook_session(r, rdata, SESSION_TUNNEL);
            int sync_rv = msrpc_sync_ready(sync_key, SESSION_TUNNEL);
            if (sync_rv == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "%s: Set Outlook Session %s successfully synchronized",
                              r->method, rdata->outlook_session);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(errno), r,
                              "%s: Failed to sync Outlook Session %s: %d",
                              r->method, rdata->outlook_session, sync_rv);
                (void)proxy_msrpc_validate_outlook_session(r, rdata, SESSION_BROKEN);
                /* Do not 'return' here as we have to clean up the broken backend connection
                   with the 'cleanup' label. */
                break;
            }
        } else if (r->method_number == msrpc_methods[MSRPC_M_DATA_IN]) {
            int8_t sync_state = msrpc_sync_wait(sync_key, 5000);
            if (sync_state == SESSION_TUNNEL) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "%s: Set Outlook Session %s successfully synchronized",
                              r->method, rdata->outlook_session);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(errno), r,
                              "%s: Failed to sync Outlook Session %s: %d",
                              r->method, rdata->outlook_session, sync_state);
                (void)proxy_msrpc_validate_outlook_session(r, rdata, SESSION_BROKEN);
                /* Do not 'return' here as we have to clean up the broken backend connection
                   with the 'cleanup' label. */
                break;
            }
        }

        /* All the subsequent traffic on this connection is RPC traffic, and there is
         * no way to downgrade the connection back to HTTP. For this reason there is
         * no point in keeping the mod_reqtimeout filter in the chain.
         * Otherwise it would close Outlook connections after the configured timeout */
        proxy_msrpc_remove_reqtimeout(r->input_filters);

        /* Step Six: tunnel traffic from backend to frontend and vice versa */
        status = proxy_msrpc_tunnel(p, r, rdata, backend);
        if (status != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r,
                          "%s: proxy_msrpc_tunnel() failed to %pI (%s)",
                          r->method, worker->cp->addr, worker->s->hostname);
        }
        /* fall through to cleanup */
        break;
    }

    /* Step Seven: Clean Up */
cleanup:
    if (backend) {
        /* unregister backend from client connection */
        ap_set_module_config(r->connection->conn_config, &proxy_msrpc_module, NULL);

        /* close backend connection */
        backend->close = 1;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "%s: handler working on backend connection 0x%pp finished, returning connection to pool",
                      r->method, backend);
        ap_proxy_release_connection(proxy_function, backend, r->server);
    }

    /* if something went wrong we should also close the client connection, otherwise Outlook will hang idle. */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "%s: setting keepalive from %d to AP_CONN_CLOSE", r->method, r->connection->keepalive);
    r->connection->keepalive = AP_CONN_CLOSE;
    apr_socket_close(ap_get_conn_socket(r->connection));
    r->connection->aborted = 1;

    return status;
}

static void proxy_msrpc_register_hook(apr_pool_t *p)
{
    static const char *const before_module[] = { "mod_proxy_http.c", NULL};
    ap_hook_pre_config(proxy_msrpc_precfg, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(proxy_msrpc_init, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_child_init(proxy_msrpc_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    proxy_hook_scheme_handler(proxy_msrpc_handler, NULL, before_module, APR_HOOK_FIRST);
}

static const char *set_outlook_anywhere_passthrough(cmd_parms *parms,
                                                    void *dummy, int flag)
{
    proxy_msrpc_conf_t *conf;
    conf = (proxy_msrpc_conf_t *)ap_get_module_config(parms->server->module_config,
                                                      &proxy_msrpc_module);
    conf->enabled = flag;
    conf->enabled_set = 1;
    proxy_msrpc_configured = 1;
    return NULL;
}

static const char *set_outlook_anywhere_user_agents(cmd_parms *cmd, void *cfg, const char* arg)
{
    server_rec *s = cmd->server;
    proxy_msrpc_conf_t *conf = ap_get_module_config(s->module_config, &proxy_msrpc_module);
    assert(conf != NULL);
    if (!conf->user_agents) {
        conf->user_agents = apr_array_make(cmd->pool, 2, sizeof(const char*));
    }
    const char **user_agent = apr_array_push(conf->user_agents);
    *user_agent = arg;
    return NULL;
}

static const char *set_outlook_anywhere_socache(cmd_parms *cmd, void *CFG,
                                       const char *arg)
{
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (errmsg)
        return errmsg;
    msrpc_session_cache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, arg,
                                                      AP_SOCACHE_PROVIDER_VERSION);
    if (msrpc_session_cache_provider == NULL) {
        errmsg = apr_psprintf(cmd->pool,
                              "Unknown socache provider '%s'. Maybe you need "
                              "to load the appropriate socache module "
                              "(mod_socache_%s?)", arg, arg);
    }
    return errmsg;
}

static const char *set_outlook_anywhere_cache_expiry(cmd_parms *cmd, void *CFG,
                                                     const char *arg)
{
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (errmsg)
        return errmsg;

    apr_interval_time_t value = apr_atoi64(arg);
    if (errno != 0) {
        return apr_psprintf(cmd->pool, "failed to parse '%s'", arg);
    }
    if (value < 1000000) {
        return "value needs to be larger than 1000000";
    }
    msrpc_session_cache_expiry = value;
    return NULL;
}

static void *create_msrpc_config(apr_pool_t *p, server_rec *s)
{
    proxy_msrpc_conf_t *c = apr_pcalloc(p, sizeof(proxy_msrpc_conf_t));
    return c;
}

static void *merge_msrpc_config(apr_pool_t *p, void *basev, void *overridesv)
{
    proxy_msrpc_conf_t *new_c = apr_pcalloc(p, sizeof(proxy_msrpc_conf_t));
    proxy_msrpc_conf_t *base = (proxy_msrpc_conf_t *)basev;
    proxy_msrpc_conf_t *overrides = (proxy_msrpc_conf_t *)overridesv;

    new_c->enabled = (overrides->enabled_set == 0)
                     ? base->enabled
                     : overrides->enabled;
    if (overrides->user_agents) {
        new_c->user_agents = apr_array_copy_hdr(p, overrides->user_agents);
    }
    return new_c;
}

static const command_rec proxy_msrpc_cmds[] =
{
    AP_INIT_FLAG("OutlookAnywherePassthrough", set_outlook_anywhere_passthrough,
                 NULL, RSRC_CONF, "Enable passthrough of Outlook Anywhere traffic"),
    AP_INIT_ITERATE("OutlookAnywhereUserAgents", set_outlook_anywhere_user_agents,
                 NULL, RSRC_CONF, "User-Agents that should be treated as Outlook Anywhere"),
    AP_INIT_TAKE1("OutlookAnywhereSOCache", set_outlook_anywhere_socache,
                 NULL, RSRC_CONF, "SOCache provider for Outlook Anywhere"),
    AP_INIT_TAKE1("OutlookAnywhereSOCacheExpire", set_outlook_anywhere_cache_expiry,
                 NULL, RSRC_CONF, "Expiry for Outlook Anywhere session cache"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA proxy_msrpc_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    create_msrpc_config,    /* create per-server config structure */
    merge_msrpc_config,     /* merge per-server config structures */
    proxy_msrpc_cmds,       /* command apr_table_t */
    proxy_msrpc_register_hook  /* register hooks */
};
