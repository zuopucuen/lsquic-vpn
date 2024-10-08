/*
 * prog.h -- common setup and options for QUIC program
 */

#ifndef PROG_H
#define PROG_H 1

#include "config.h"

struct event;
struct event_base;
struct lsquic_hash;
struct sport_head;
struct ssl_ctx_st;
struct lsquic_vpn_ctx_s;

struct prog
{
    struct packout_buf_allocator    prog_pba;
    struct lsquic_engine_settings   prog_settings;
    struct lsquic_engine_api        prog_api;
    unsigned                        prog_engine_flags;
    struct service_port             prog_dummy_sport;   /* Use for options */
    unsigned                        prog_packout_max;
    unsigned short                  prog_max_packet_size;
    int                             prog_version_cleared;
    unsigned long                   prog_read_count;
#if HAVE_SENDMMSG
    int                             prog_use_sendmmsg;
#endif
#if HAVE_RECVMMSG
    int                             prog_use_recvmmsg;
#endif
    int                             prog_use_stock_pmi;
    struct event_base              *prog_eb;
    struct event                   *prog_timer,
                                   *prog_send,
                                   *prog_sigint,
                                   *prog_sigterm;
    struct ssl_ctx_st              *prog_ssl_ctx;
    struct lsquic_hash             *prog_certs;
    struct event                   *prog_event_sni;
    char                           *prog_susp_sni;
    struct sport_head              *prog_sports;
    struct lsquic_engine           *prog_engine;
    const char                     *prog_hostname;
    const char                     *certs_optarg;
    const char                     *ca_file;
    const char                     *cert_file;
    const char                     *key_file;
    int                             prog_ipver;     /* 0, 4, or 6 */
    enum {
        PROG_FLAG_COOLDOWN  = 1 << 0,
#if LSQUIC_PREFERRED_ADDR
        PROG_SEARCH_ADDRS   = 1 << 1,
#endif
    }                               prog_flags;
    struct lsquic_vpn_ctx_s        *lsquic_vpn_ctx;
};

int
prog_init (struct prog *, unsigned lsquic_engine_flags, struct sport_head *,
                    const struct lsquic_stream_if *, void *stream_if_ctx);

#if HAVE_SENDMMSG
#   define SENDMMSG_FLAG "g"
#else
#   define SENDMMSG_FLAG ""
#endif
#if HAVE_RECVMMSG
#   define RECVMMSG_FLAG "j"
#else
#   define RECVMMSG_FLAG ""
#endif

#if LSQUIC_DONTFRAG_SUPPORTED
#   define IP_DONTFRAG_FLAG "D"
#else
#   define IP_DONTFRAG_FLAG ""
#endif

#define MAX_LINE_LENGTH 256
#define MAX_KEY_LENGTH 64

struct event_base *
prog_eb (struct prog *);

int
prog_run (struct prog *);

void
prog_cleanup (struct prog *);

void
prog_stop (struct prog *);

int
prog_prep (struct prog *);

int
prog_connect (struct prog *, unsigned char *, size_t);

void
prog_print_common_options (const struct prog *, FILE *);

int
prog_is_stopped (void);

void
prog_process_conns (struct prog *);

void
prog_sport_cant_send (struct prog *, int fd);

int 
prog_parse_config_file(struct prog *prog, const char *filename);

#endif
