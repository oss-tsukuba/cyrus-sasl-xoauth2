/*
 * Copyright (c) 2016 Moriyoshi Koizumi
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "xoauth2_plugin.h"

#define DATA_SIZE 65536
#define POST_DATA "client_id=%s&client_secret=%s&token=%s"

struct memory {
  char *response;
  size_t size;
};

size_t memory_writer(
        char *data,
        size_t size,
        size_t nmemb,
        void *stream)
{
    size_t datasize  = size * nmemb;
    struct memory *mem = stream;

    char *ptr = realloc(mem->response, mem->size + datasize + 1);
    if (ptr == NULL)
        return 0; /* out of memory */

    mem->response = ptr;
    memcpy(&mem->response[mem->size], data, datasize);
    mem->size += datasize;
    mem->response[mem->size] = '\0';

    return datasize;
}

int introspect_token(
        xoauth2_plugin_server_settings_t *settings,
        sasl_server_params_t *params,
        char *user,
        char *token,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
 
    CURL *curl;
    struct curl_slist *headers = NULL;
    char errbuf[CURL_ERROR_SIZE];
    char post_data[DATA_SIZE];
    int post_ret = 0;
    int ret = 1;

    struct memory buf;
    buf.response = NULL;
    buf.size = 0;

    // set data
    snprintf(post_data, sizeof post_data, POST_DATA, settings->client_id, settings->client_secret, token);

    curl = curl_easy_init();

    // buffer to store errors
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    // HEADER
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // POST
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));

    // URL
    curl_easy_setopt(curl, CURLOPT_URL, settings->introspection_url);

    // callback
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, memory_writer);

    post_ret = curl_easy_perform(curl);

    if (post_ret != CURLE_OK) {
        SASL_log((utils->conn, SASL_LOG_ERR, "user %s: curl_easy_perform = %d: %s", user, post_ret, errbuf));
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (post_ret == 0) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "user %s: data:%s", user, buf.response));

        json_object *result = json_tokener_parse(buf.response);

        if (result == NULL) {
            SASL_log((utils->conn, SASL_LOG_ERR, "user %s: parsed JSON is NULL"));
        } else {
            json_object *active = NULL;

            if (json_object_object_get_ex(result, "active", &active) &&
                json_object_get_boolean(active)) {
                json_object *userobj = NULL;

                if (json_object_object_get_ex(result, "username", &userobj)) {
                    const char *username = json_object_get_string(userobj);

                    oparams->authid = username;

                    if (strcmp(user, username) == 0) {
                        // success
                        ret = 0;
                        SASL_log((utils->conn, SASL_LOG_NOTE, "user %s: auth success", user));
                    } else {
                        SASL_log((utils->conn, SASL_LOG_NOTE, "user %s: JWT username %s mismatch", user, username));
                    }
                } else {
                    SASL_log((utils->conn, SASL_LOG_NOTE, "user %s: active, but no username", user));
                }
            } else {
                SASL_log((utils->conn, SASL_LOG_NOTE, "user %s: inactive", user));
            }
            json_object_put(result);
        }
    }

    free(buf.response);

    return ret;
}

static int xoauth2_plugin_server_mech_new(
        void *glob_context, 
        sasl_server_params_t *params,
        UNUSED(const char *challenge),
        UNUSED(unsigned challenge_len),
        void **pcontext)
{
    int err;
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_server_context_t *context;

    context = SASL_malloc(sizeof(*context));
    if (!context) {
        SASL_seterror((utils->conn, 0, "Failed to allocate memory"));
        return SASL_NOMEM;
    }

    context->settings = (xoauth2_plugin_server_settings_t *)glob_context;
    context->state = 0;
    context->resp.buf = NULL;
    err = xoauth2_plugin_str_init(utils, &context->outbuf);
    if (err != SASL_OK) {
        SASL_free(context);
        SASL_log((utils->conn, SASL_LOG_ERR, "failed to allocate buffer"));
        return err;
    }
    *pcontext = context;
    return SASL_OK;
}

static int append_string(const sasl_utils_t *utils, xoauth2_plugin_str_t *outbuf, const char *v, unsigned vlen)
{
    int err;
    const char *p;
    const char *e = v + vlen;
    err = xoauth2_plugin_str_alloc(utils, outbuf, outbuf->len + 2 + vlen * 2);
    if (err != SASL_OK) {
        return err;
    }
    outbuf->buf[outbuf->len++] = '"';
    for (p = v; p < e; ++p) {
        switch (*p) {
        case 8:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'b';
            break;
        case 9:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 't';
            break;
        case 10:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'n';
            break;
        case 12:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'f';
            break;
        case 13:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'r';
            break;
        case '"': case '\\':
            outbuf->buf[outbuf->len++] = '\\';
            /* fall-through */ 
        default:
            outbuf->buf[outbuf->len++] = *p;
            break;
        }
    }
    outbuf->buf[outbuf->len++] = '"';
    return SASL_OK; 
}

static int append_int(const sasl_utils_t *utils, xoauth2_plugin_str_t *outbuf, int n)
{
    int err;
    char buf[1024];
    int len = snprintf(buf, sizeof(buf) - 1, "%d", n);
    if (len < 0) {
        return SASL_NOMEM; 
    }
    return xoauth2_plugin_str_append(utils, outbuf, buf, (unsigned)len);
}

static int build_json_response(const sasl_utils_t *utils, xoauth2_plugin_str_t *outbuf, const char *status, xoauth2_plugin_server_settings_t *settings, xoauth2_plugin_auth_response_t *resp)
{
    int err;
    err = xoauth2_plugin_str_append(utils, outbuf, "{", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, "status", 6);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ":", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, status, strlen(status));
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ",", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, "schemes", 6);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ":", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, resp->token_type, resp->token_type_len);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ",", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, "scope", 5);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ":", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, settings->scope, settings->scope_len);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, "}", 1);
    if (err != SASL_OK) {
        return err;
    }
    return SASL_OK;
}

static int xoauth2_plugin_server_mech_step1(
        void *_context,
        sasl_server_params_t *params,
        const char *clientin,
        unsigned clientin_len,
        const char **serverout,
        unsigned *serverout_len,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_server_context_t *context = _context;
    int err = SASL_OK;
    xoauth2_plugin_auth_response_t resp;
    int token_is_valid = 0;

    *serverout = NULL;
    *serverout_len = 0;

    SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2: step1"));
    
    if (!context) {
        err = SASL_BADPROT;
        goto out;
    }

    if (!clientin) {
        err = SASL_BADPROT;
        goto out;
    }

    {
        char *p, *e, *token_e;
        resp.buf = SASL_malloc(clientin_len + 1);
        if (!resp.buf) {
            SASL_seterror((utils->conn, 0, "Failed to allocate memory"));
            err = SASL_NOMEM;
            goto out;
        }
        memcpy(resp.buf, clientin, clientin_len);
        resp.buf[clientin_len] = '\0';
        resp.buf_size = clientin_len;

        p = resp.buf, e = resp.buf + resp.buf_size;

        if (e - p < 5 || strncasecmp(p, "user=", 5) != 0) {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
            err = SASL_BADPROT;
            goto out;
        }
        p += 5;

        resp.authid = p;
        for (;;) {
            if (p >= e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p == '\001') {
                break;
            }
            ++p;
        }
        *p = '\0';
        resp.authid_len = p - resp.authid;
        ++p;

        if (e - p < 5 || strncasecmp(p, "auth=", 5) != 0) {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
            err = SASL_BADPROT;
            goto out;
        }

        p += 5;

        resp.token_type = p;
        for (;;) {
            if (p >= e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p == '\001') {
                break;
            }
            ++p;
        }
        *p = '\0';
        token_e = p;

        if (*++p != '\001') {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
            err = SASL_BADPROT;
            goto out;
        }
        if (p + 1 != e) {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
            err = SASL_BADPROT;
            goto out;
        }

        p = resp.token_type;
        for (;;) {
            if (p >= token_e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p == ' ') {
                break;
            }
            ++p;
        }
        *p = '\0';
        resp.token_type_len = p - resp.token_type;
        ++p;

        for (;;) {
            if (p >= token_e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information"));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p != ' ') {
                break;
            }
            ++p;
        }
        resp.token = p;
        resp.token_len = token_e - resp.token;
    }

    if (resp.token_type_len != 6 || strncasecmp(resp.token_type, "bearer", 6) != 0) {
        /* not sure if we can return a plain error instead of a challange-impersonated error */
        err = SASL_BADPROT;
        SASL_seterror((utils->conn, 0, "unsupported token type: %s", resp.token_type));
        goto out;
    }

    {
        const char *requests[] = { SASL_AUX_OAUTH2_BEARER_TOKENS, NULL };
        struct propval vals[1];
        const char **p;
        int nprops;

        err = utils->prop_request(params->propctx, requests);
        if (err != SASL_OK) {
            /* not sure if we can return a plain error instead of a challange-impersonated error at this point */
            SASL_seterror((utils->conn, 0, "failed to retrieve bearer tokens for the user %s", resp.authid));
            goto out;
        }

        // canon_user instead
        oparams->user = resp.authid;
        oparams->authid = resp.authid;

        err = introspect_token(context->settings, params, resp.authid, resp.token, oparams);

        if (err == SASL_OK) {
            token_is_valid = 1;
        }
    }

    if (!token_is_valid) {
        err = build_json_response(utils, &context->outbuf, "401", context->settings, &resp);
        if (err != SASL_OK) {
            SASL_log((utils->conn, SASL_LOG_ERR, "failed to allocate buffer"));
            goto out;
        }
        context->state = 1;
        context->resp = resp, resp.buf = NULL;
        *serverout = context->outbuf.buf;
        *serverout_len = context->outbuf.len;
        err = SASL_CONTINUE;
        goto out;
    }

out:
    if (resp.buf != NULL) {
        memset(resp.buf, 0, resp.buf_size);
        SASL_free(resp.buf);
    }
    return err;
}

static int xoauth2_plugin_server_mech_step2(
        void *_context,
        sasl_server_params_t *params,
        const char *clientin,
        unsigned clientin_len,
        const char **serverout,
        unsigned *serverout_len,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_server_context_t *context = _context;

    *serverout = NULL;
    *serverout_len = 0;

    SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2: step2"));
    
    if (!context) {
        return SASL_BADPROT;
    }

    //    SASL_seterror((utils->conn, 0, "bearer token is not valid: %s", context->resp.token));
    //    return params->transition ? SASL_TRANS: SASL_NOUSER;
    return SASL_FAIL;
}

static int xoauth2_plugin_server_mech_step(
        void *_context,
        sasl_server_params_t *params,
        const char *clientin,
        unsigned clientin_len,
        const char **serverout,
        unsigned *serverout_len,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_server_context_t *context = _context;
    switch (context->state) {
    case 0:
        return xoauth2_plugin_server_mech_step1(
            context, params,
            clientin, clientin_len,
            serverout, serverout_len,
            oparams);
    case 1:
        return xoauth2_plugin_server_mech_step2(
            context, params,
            clientin, clientin_len,
            serverout, serverout_len,
            oparams);
    default:
        return SASL_BADPROT;
    }
}

static void xoauth2_plugin_server_mech_dispose(void *_context, const sasl_utils_t *utils)
{
    xoauth2_plugin_server_context_t *context = _context;

    if (!context) {
        return;
    }

    if (context->resp.buf) {
        memset(context->resp.buf, 0, context->resp.buf_size);
        SASL_free(context->resp.buf);
        context->resp.buf = NULL;
    }
    xoauth2_plugin_str_free(utils, &context->outbuf);
    SASL_free(context);
}

static int xoauth2_server_plug_get_options(sasl_utils_t *utils, xoauth2_plugin_server_settings_t *settings)
{
    int err;

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "client_id",
            &settings->client_id, &settings->client_id_len);
    if (err != SASL_OK || !settings->client_id) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "client_id is not set"));
        settings->client_id = "";
        settings->client_id_len = 0;
    }

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "client_secret",
            &settings->client_secret, &settings->client_secret_len);
    if (err != SASL_OK || !settings->client_secret) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "client_secret is not set"));
        settings->client_secret = "";
        settings->client_secret_len = 0;
    }

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "introspection_url",
            &settings->introspection_url, &settings->introspection_url_len);
    if (err != SASL_OK || !settings->introspection_url) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "introspection_url is not set"));
        settings->introspection_url = "";
        settings->introspection_url_len = 0;
    }

    return SASL_OK;
}
    
static xoauth2_plugin_server_settings_t xoauth2_server_settings;

static sasl_server_plug_t xoauth2_server_plugins[] = 
{
    {
        "XOAUTH2",                              /* mech_name */
        0,                                      /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS,            /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST
        | SASL_FEAT_ALLOWS_PROXY,               /* features */
        NULL,                                   /* glob_context */
        &xoauth2_plugin_server_mech_new,        /* mech_new */
        &xoauth2_plugin_server_mech_step,       /* mech_step */
        &xoauth2_plugin_server_mech_dispose,    /* mech_dispose */
        NULL,                                   /* mech_free */
        NULL,                                   /* setpass */
        NULL,                                   /* user_query */
        NULL,                                   /* idle */
        NULL,                                   /* mech_avail */
        NULL                                    /* spare */
    }
};

int xoauth2_server_plug_init(
        sasl_utils_t *utils,
        int maxversion,
        int *out_version,
        sasl_server_plug_t **pluglist,
        int *plugcount)
{
    int err;

    if (maxversion < SASL_SERVER_PLUG_VERSION) {
        SASL_seterror((utils->conn, 0, "xoauth2: version mismatch"));
        return SASL_BADVERS;
    }

    err = xoauth2_server_plug_get_options(utils, &xoauth2_server_settings);
    if (err != SASL_OK) {
        return err;
    }

    xoauth2_server_plugins[0].glob_context = &xoauth2_server_settings;

    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = xoauth2_server_plugins;
    *plugcount = sizeof(xoauth2_server_plugins) / sizeof(*xoauth2_server_plugins);
    
    return SASL_OK;
}
