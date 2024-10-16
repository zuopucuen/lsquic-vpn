#ifndef TEST_CERT_H
#define TEST_CERT_H

#include <openssl/x509.h>

struct lsquic_hash;
struct ssl_ctx_st;
struct sockaddr;

struct server_cert {
    char                *ce_sni;
    struct ssl_ctx_st   *ce_ssl_ctx;
    struct lsquic_hash_elem ce_hash_el;
};

int
load_cert(struct lsquic_hash *certs, const char *ca_file, const char *cert_file, const char *key_file);

int
set_cert(SSL_CTX *ssl_ctx, const char *ca_file, const char *cert_file, const char *key_file);

struct ssl_ctx_st *
lookup_cert(void *cert_lu_ctx, const struct sockaddr *UNUSED,
            const char *sni);

void
delete_certs(struct lsquic_hash *certs);

int
add_alpn(const char *alpn);

#endif  // TEST_CERT_H