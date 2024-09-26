#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <unistd.h>

#include <event2/event.h>
#include <openssl/ssl.h>

#include <lsquic.h>
#include <lsquic_hash.h>
#include <lsquic_int_types.h>
#include <lsquic_util.h>
#include <lsquic_logger.h>

#include "config.h"
#include "cert.h"
#include "common.h"
#include "prog.h"
#include "vpn.h"
#include "os.h"

static int prog_stopped;
static const char *s_keylog_dir;
static const char *s_sess_resume_file;

static SSL_CTX * get_ssl_ctx (void *, const struct sockaddr *);
static void keylog_log_line (const SSL *, const char *);

static const struct lsquic_packout_mem_if pmi = {
    .pmi_allocate = pba_allocate,
    .pmi_release  = pba_release,
    .pmi_return   = pba_release,
};


int
prog_init (struct prog *prog, unsigned flags,
           struct sport_head *sports,
           const struct lsquic_stream_if *stream_if, void *stream_if_ctx)
{
    /* prog-specific initialization: */
    memset(prog, 0, sizeof(*prog));
    prog->prog_engine_flags = flags;
    prog->prog_sports       = sports;
    lsquic_engine_init_settings(&prog->prog_settings, flags);
#if ECN_SUPPORTED
    prog->prog_settings.es_ecn      = LSQUIC_DF_ECN;
#else
    prog->prog_settings.es_ecn      = 0;
#endif
    prog->prog_settings.es_idle_timeout = 300;
    prog->prog_settings.es_cc_algo = 2; // BBRv1
    
    /*
    prog->prog_settings.es_cfcw = 1024 * 1024 * 1;
    prog->prog_settings.es_max_cfcw = 1024 * 1024 * 2;
    prog->prog_settings.es_sfcw = 16 * 1024;
    prog->prog_settings.es_max_sfcw = 64 * 1024;
    */

    prog->prog_api.ea_settings      = &prog->prog_settings;
    prog->prog_api.ea_stream_if     = stream_if;
    prog->prog_api.ea_stream_if_ctx = stream_if_ctx;
    prog->prog_api.ea_packets_out   = sport_packets_out;
    prog->prog_api.ea_packets_out_ctx
                                    = prog;
    prog->prog_api.ea_pmi           = &pmi;
    prog->prog_api.ea_pmi_ctx       = &prog->prog_pba;
    prog->prog_api.ea_get_ssl_ctx   = get_ssl_ctx;
#if LSQUIC_PREFERRED_ADDR
    if (getenv("LSQUIC_PREFERRED_ADDR4") || getenv("LSQUIC_PREFERRED_ADDR6"))
        prog->prog_flags |= PROG_SEARCH_ADDRS;
#endif

    /* Non prog-specific initialization: */
    lsquic_global_init(flags & LSENG_SERVER ? LSQUIC_GLOBAL_SERVER :
                                                    LSQUIC_GLOBAL_CLIENT);
    lsquic_log_to_fstream(stderr,  LLTS_YYYYMMDD_HHMMSSMS);
    lsquic_logger_lopt("=notice");
    return 0;
}


static int
prog_add_sport (struct prog *prog, const char *arg)
{
    struct service_port *sport;
    sport = sport_new(arg, prog);
    if (!sport)
        return -1;
    /* Default settings: */
    sport->sp_flags |= SPORT_SET_SNDBUF;
    sport->sp_flags |= SPORT_SET_SNDBUF;
    sport->sp_sndbuf = 1024 * 1024;
    sport->sp_rcvbuf = 1024 * 16;
    TAILQ_INSERT_TAIL(prog->prog_sports, sport, next_sport);
    return 0;
}


void
prog_print_common_options (const struct prog *prog, FILE *out)
{
    fprintf(out,
"   -c          configure file\n"
"   -h          Print this help screen and exit\n"
    );
}

static int
    tut_log_buf (void *ctx, const char *buf, size_t len) {
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}

// 去除字符串首尾的空白字符
static char *trim(char *str) {
    char *end;
 
    // 去除开头的空白字符
    while (isspace(*str)) {
        str++;
    }
 
    // 去除尾部的空白字符
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        end--;
    }
 
    // 在空白字符处结束字符串
    *(end + 1) = '\0';
 
    return str;
}

int prog_parse_config_file(struct prog *prog, const char *filename) {
    char line[MAX_LINE_LENGTH];
    char key[MAX_KEY_LENGTH];
    char *value;
    char *split_char = "=";
    char *tmp;
    size_t key_length, value_length;
    tun_t *tun;
    int i,j;
    struct service_port *sport;
    
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("打开配置文件时出错");
        return 1;
    }
 
    while (fgets(line, sizeof(line), file) != NULL) {       
        // 忽略注释和空行
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
 
        // 分割行，获取键和值
        char *token = strtok(line, split_char);

        if (token != NULL) {    
            token = trim(token);
            strncpy(key, token, sizeof(key) - 1);
            key_length = strlen(key);
            key[key_length] = '\0';
 
            token = strtok(NULL, split_char);
            if (token != NULL) {
                token = trim(token);
                value_length = strlen(token);
                value = (char *)malloc(value_length + 1);
                strncpy(value, token, value_length);
                value[value_length] = '\0';
            }

            if (strcmp("server", key) == 0){
                if (0 == (prog->prog_engine_flags & LSENG_SERVER) &&
                                            !TAILQ_EMPTY(prog->prog_sports)){
                    perror("server addr or port error");
                    return 1;
                }
                prog_add_sport(prog, value);  
            }else if (strcmp("set_route", key) == 0){
                if (strcmp("yes", value) == 0){
                    prog->lsquic_vpn_ctx->set_route = 1;
                }else{
                    perror("value error, please use 'yes' or 'no'");
                    return 1;
                }
            }else if (strcmp("cert", key) == 0){
                prog->cert_file = value;
            }else if (strcmp("key", key) == 0){
                prog->key_file = value;
            }else if (strcmp("ca", key) == 0){
                prog->ca_file = value;
            }else if (strcmp("log_file", key) == 0){
                FILE *log_file;
                log_file = fopen(value, "wb");
                if (file == NULL) {
                    perror("Error opening file");
                    return 1;
                }

                static const struct lsquic_logger_if logger_if = { tut_log_buf, };
                lsquic_logger_init(&logger_if, log_file, LLTS_YYYYMMDD_HHMMSSMS);
                
            }else if (strcmp("log_level", key) == 0){
                lsquic_set_log_level(value);
            }else if (strcmp("ip_route", key) == 0){
                i = 0;

                tun = malloc(sizeof(tun_t));
                memset(tun, 0, sizeof(tun_t));
                tun->is_server = prog->lsquic_vpn_ctx->is_server;
                tun->set_route = prog->lsquic_vpn_ctx->set_route;

                sport = TAILQ_LAST(prog->prog_sports, sport_head);
                tun->server_ip = sport->host;
                tun->ext_gw_ip = get_default_gw_ip();

                if(prog->lsquic_vpn_ctx->tun == NULL){
                    prog->lsquic_vpn_ctx->tun = tun;
                }else{
                    prog->lsquic_vpn_ctx->tun->next = tun;
                }

                if(prog->lsquic_vpn_ctx->is_server){
                    tun->local_tun_ip = value;
                }else{
                    tun->remote_tun_ip = value;
                }

                while(*(value+1) != '\0'){
                    if(*value == ','){
                        *value = '\0';
                        if(i == 0){
                            i++;
                            value++;
                            if(prog->lsquic_vpn_ctx->is_server){
                                tun->remote_tun_ip = value;
                            }else{
                                tun->local_tun_ip = value;
                            }
                            continue;
                        }else{
                        }
                    }
                    value++;
                }
                if(prog->lsquic_vpn_ctx->is_server)
                    tun_init(tun);
            }
        }
    }
 
    fclose(file);
    return 0;
}

struct event_base *
prog_eb (struct prog *prog)
{
    return prog->prog_eb;
}


int
prog_connect (struct prog *prog, unsigned char *sess_resume, size_t sess_resume_len)
{
    struct service_port *sport;

    sport = TAILQ_FIRST(prog->prog_sports);
    if (NULL == lsquic_engine_connect(prog->prog_engine, LSQVER_ID29,
                    (struct sockaddr *) &sport->sp_local_addr,
                    (struct sockaddr *) &sport->sas, sport, NULL,
                    prog->prog_hostname ? prog->prog_hostname
                    /* SNI is required for HTTP */
                  : prog->prog_engine_flags & LSENG_HTTP ? sport->host
                  : NULL,
                    prog->prog_max_packet_size, sess_resume, sess_resume_len,
                    sport->sp_token_buf, sport->sp_token_sz))
        return -1;

    prog_process_conns(prog);
    return 0;
}


static int
prog_init_client (struct prog *prog)
{
    struct service_port *sport;

    sport = TAILQ_FIRST(prog->prog_sports);
    if (0 != sport_init_client(sport, prog->prog_engine, prog->prog_eb))
        return -1;

    return 0;
}


static SSL_CTX *
get_ssl_ctx (void *peer_ctx, const struct sockaddr *unused)
{
    const struct service_port *const sport = peer_ctx;
    return sport->sp_prog->prog_ssl_ctx;
}


static int
prog_new_session_cb (SSL *ssl, SSL_SESSION *session)
{
    unsigned char *buf;
    size_t bufsz, nw;
    FILE *file;

    /* Our client is rather limited: only one file and only one ticket
     * can be saved.  A more flexible client implementation would call
     * lsquic_ssl_to_conn() and maybe save more tickets based on its
     * own configuration.
     */
    if (!s_sess_resume_file)
        return 0;

    if (0 != lsquic_ssl_sess_to_resume_info(ssl, session, &buf, &bufsz))
    {
        LSQ_NOTICE("lsquic_ssl_sess_to_resume_info failed");
        return 0;
    }

    file = fopen(s_sess_resume_file, "wb");
    if (!file)
    {
        LSQ_WARN("cannot open %s for writing: %s",
            s_sess_resume_file, strerror(errno));
        free(buf);
        return 0;
    }

    nw = fwrite(buf, 1, bufsz, file);
    if (nw == bufsz)
    {
        LSQ_INFO("wrote %zd bytes of session resumption information to %s",
            nw, s_sess_resume_file);
        s_sess_resume_file = NULL;  /* Save just one ticket */
    }
    else
        LSQ_WARN("error: fwrite(%s) returns %zd instead of %zd: %s",
            s_sess_resume_file, nw, bufsz, strerror(errno));

    fclose(file);
    free(buf);
    return 0;
}

static int
prog_init_ssl_ctx (struct prog *prog)
{
    unsigned char ticket_keys[48];

    prog->prog_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!prog->prog_ssl_ctx)
    {
        LSQ_ERROR("cannot allocate SSL context");
        return -1;
    }

    if(set_cert(prog->prog_ssl_ctx, prog->ca_file, prog->cert_file, prog->key_file) <=0){
        return -1;
    }

    /* This is obviously test code: the key is just an array of NUL bytes */
    memset(ticket_keys, 0, sizeof(ticket_keys));
    if (1 != SSL_CTX_set_tlsext_ticket_keys(prog->prog_ssl_ctx,
                                        ticket_keys, sizeof(ticket_keys)))
    {
        LSQ_ERROR("SSL_CTX_set_tlsext_ticket_keys failed");
        return -1;
    }

    if (s_keylog_dir)
        SSL_CTX_set_keylog_callback(prog->prog_ssl_ctx, keylog_log_line);

    if (s_sess_resume_file)
    {
        SSL_CTX_set_session_cache_mode(prog->prog_ssl_ctx,
                                                    SSL_SESS_CACHE_CLIENT);
        SSL_CTX_set_early_data_enabled(prog->prog_ssl_ctx, 1);
        SSL_CTX_sess_set_new_cb(prog->prog_ssl_ctx, prog_new_session_cb);
    }

    return 0;
}


static int
prog_init_server (struct prog *prog)
{
    struct service_port *sport;

    TAILQ_FOREACH(sport, prog->prog_sports, next_sport)
        if (0 != sport_init_server(sport, prog->prog_engine, prog->prog_eb))
            return -1;

    return 0;
}


void
prog_process_conns (struct prog *prog)
{
    int diff;
    struct timeval timeout;

    lsquic_engine_process_conns(prog->prog_engine);

    if (lsquic_engine_earliest_adv_tick(prog->prog_engine, &diff))
    {
        if (diff < 0
                || (unsigned) diff < prog->prog_settings.es_clock_granularity)
        {
            timeout.tv_sec  = 0;
            timeout.tv_usec = prog->prog_settings.es_clock_granularity;
        }
        else
        {
            timeout.tv_sec = (unsigned) diff / 1000000;
            timeout.tv_usec = (unsigned) diff % 1000000;
        }

        if (!prog_is_stopped())
            event_add(prog->prog_timer, &timeout);
    }
}


static void
prog_timer_handler (int fd, short what, void *arg)
{
    struct prog *const prog = arg;
    if (!prog_is_stopped())
        prog_process_conns(prog);
}


static void
prog_signal_handler (int fd, short what, void *arg)
{
    
    struct prog *const prog = arg;
    lsquic_vpn_ctx_t *lsquic_vpn_ctx = prog->lsquic_vpn_ctx;

    LSQ_NOTICE("Got sigint, stopping engine");
    
    if (lsquic_vpn_ctx->conn_h) {
        lsquic_conn_close(lsquic_vpn_ctx->conn_h->conn);
        LSQ_NOTICE("Got sigterm, close conns");
    }   
    prog_process_conns(prog);
    prog_stop(prog);
    exit(EXIT_SUCCESS);
}


int
prog_run (struct prog *prog)
{
    prog->prog_sigint = evsignal_new(prog->prog_eb, SIGINT,
                                                    prog_signal_handler, prog);
    evsignal_add(prog->prog_sigint, NULL);
    prog->prog_sigterm = evsignal_new(prog->prog_eb, SIGTERM,
                                                    prog_signal_handler, prog);
    evsignal_add(prog->prog_sigterm, NULL);

    event_base_loop(prog->prog_eb, 0);

    return 0;
}


void
prog_cleanup (struct prog *prog)
{
    lsquic_engine_destroy(prog->prog_engine);
    event_base_free(prog->prog_eb);
    if (!prog->prog_use_stock_pmi)
        pba_cleanup(&prog->prog_pba);
    if (prog->prog_ssl_ctx)
        SSL_CTX_free(prog->prog_ssl_ctx);
    if (prog->prog_certs)
        delete_certs(prog->prog_certs);
    lsquic_global_cleanup();
}


void
prog_stop (struct prog *prog)
{
    struct service_port *sport;

    prog_stopped = 1;

    while ((sport = TAILQ_FIRST(prog->prog_sports)))
    {
        TAILQ_REMOVE(prog->prog_sports, sport, next_sport);
        sport_destroy(sport);
    }

    if (prog->prog_timer)
    {
        event_del(prog->prog_timer);
        event_free(prog->prog_timer);
        prog->prog_timer = NULL;
    }
    if (prog->prog_sigint)
    {
        event_del(prog->prog_sigint);
        event_free(prog->prog_sigint);
        prog->prog_sigint = NULL;
    }
    if (prog->prog_sigterm)
    {
        event_del(prog->prog_sigterm);
        event_free(prog->prog_sigterm);
        prog->prog_sigterm = NULL;
    }
}


static void *
keylog_open_file (const SSL *ssl)
{
    const lsquic_conn_t *conn;
    const lsquic_cid_t *cid;
    FILE *fh;
    int sz;
    char id_str[MAX_CID_LEN * 2 + 1];
    char path[PATH_MAX];

    conn = lsquic_ssl_to_conn(ssl);
    cid = lsquic_conn_id(conn);
    lsquic_hexstr(cid->idbuf, cid->len, id_str, sizeof(id_str));
    sz = snprintf(path, sizeof(path), "%s/%s.keys", s_keylog_dir, id_str);
    if ((size_t) sz >= sizeof(path))
    {
        LSQ_WARN("%s: file too long", __func__);
        return NULL;
    }
    fh = fopen(path, "ab");
    if (!fh)
        LSQ_WARN("could not open %s for appending: %s", path, strerror(errno));
    return fh;
}


static void
keylog_log_line (const SSL *ssl, const char *line)
{
    FILE *file;

    file = keylog_open_file(ssl);
    if (file)
    {
        fputs(line, file);
        fputs("\n", file);
        fclose(file);
    }
}


static struct ssl_ctx_st *
no_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni)
{
    return NULL;
}


int
prog_prep (struct prog *prog)
{
    int s, ret;
    char err_buf[100];


    if (prog->prog_engine_flags & LSENG_SERVER && !prog->prog_certs){
        prog->prog_certs = lsquic_hash_create();
        ret = load_cert(prog->prog_certs, prog->ca_file, prog->cert_file, prog->key_file);
    }

    if (s_keylog_dir && prog->prog_certs)
    {
        struct lsquic_hash_elem *el;
        struct server_cert *cert;

        for (el = lsquic_hash_first(prog->prog_certs); el;
                                el = lsquic_hash_next(prog->prog_certs))
        {
            cert = lsquic_hashelem_getdata(el);
            SSL_CTX_set_keylog_callback(cert->ce_ssl_ctx, keylog_log_line);
        }
    }

    if (0 != lsquic_engine_check_settings(prog->prog_api.ea_settings,
                        prog->prog_engine_flags, err_buf, sizeof(err_buf)))
    {
        LSQ_ERROR("Error in settings: %s", err_buf);
        return -1;
    }

    if (!prog->prog_use_stock_pmi)
        pba_init(&prog->prog_pba, prog->prog_packout_max);
    else
    {
        prog->prog_api.ea_pmi = NULL;
        prog->prog_api.ea_pmi_ctx = NULL;
    }

    if (TAILQ_EMPTY(prog->prog_sports))
    {
        if (prog->prog_hostname)
            s = prog_add_sport(prog, prog->prog_hostname);
        else
            s = prog_add_sport(prog, "0.0.0.0:12345");
        if (0 != s)
            return -1;
    }

    if (prog->prog_certs)
    {
    prog->prog_api.ea_lookup_cert = lookup_cert;
    prog->prog_api.ea_cert_lu_ctx = prog->prog_certs;
    }
    else
    {
        if (prog->prog_engine_flags & LSENG_SERVER)
            LSQ_WARN("Not a single service specified.  Use -c option.");
        prog->prog_api.ea_lookup_cert = no_cert;
    }

    prog->prog_eb = event_base_new();
    prog->prog_engine = lsquic_engine_new(prog->prog_engine_flags,
                                                            &prog->prog_api);
    if (!prog->prog_engine)
        return -1;

    prog->prog_timer = event_new(prog->prog_eb, -1, 0,
                                        prog_timer_handler, prog);

    if (0 != prog_init_ssl_ctx(prog))
        return -1;

    if (prog->prog_engine_flags & LSENG_SERVER)
        s = prog_init_server(prog);
    else
        s = prog_init_client(prog);

    if (s != 0)
        return -1;

    return 0;
}


int
prog_is_stopped (void)
{
    return prog_stopped != 0;
}


static void
send_unsent (evutil_socket_t fd, short what, void *arg)
{
    struct prog *const prog = arg;
    assert(prog->prog_send);
    event_del(prog->prog_send);
    event_free(prog->prog_send);
    prog->prog_send = NULL;
    LSQ_DEBUG("on_write event fires");
    lsquic_engine_send_unsent_packets(prog->prog_engine);
}


void
prog_sport_cant_send (struct prog *prog, int fd)
{
    assert(!prog->prog_send);
    LSQ_DEBUG("cannot send: register on_write event");
    prog->prog_send = event_new(prog->prog_eb, fd, EV_WRITE, send_unsent, prog);
    event_add(prog->prog_send, NULL);
}
