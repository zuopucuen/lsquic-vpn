#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <lsquic.h>
#include <lsquic_types.h>
#include <lsquic_logger.h>
#include <lsquic_hash.h>

#include "cert.h"


static char s_alpn[0x100];

int
add_alpn (const char *alpn)
{
    size_t alpn_len, all_len;

    alpn_len = strlen(alpn);
    if (alpn_len > 255)
        return -1;

    all_len = strlen(s_alpn);
    if (all_len + 1 + alpn_len + 1 > sizeof(s_alpn))
        return -1;

    s_alpn[all_len] = alpn_len;
    memcpy(&s_alpn[all_len + 1], alpn, alpn_len);
    s_alpn[all_len + 1 + alpn_len] = '\0';
    return 0;
}


static int
select_alpn (SSL *ssl, const unsigned char **out, unsigned char *outlen,
                    const unsigned char *in, unsigned int inlen, void *arg)
{
    int r;

    r = SSL_select_next_proto((unsigned char **) out, outlen, in, inlen,
                                    (unsigned char *) s_alpn, strlen(s_alpn));
    if (r == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    else
    {
        LSQ_WARN("no supported protocol can be selected from %.*s",
                                                    (int) inlen, (char *) in);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    X509 *cert;
    char data[256];

    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        LSQ_EMERG("OpenSSL pre-verification error: %s\n", X509_verify_cert_error_string(err));
        return preverify_ok;
    }

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (!cert) return 0;

    ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serialNumber, NULL);
    char *serial = BN_bn2hex(bn);
    LSQ_INFO("serialNumber: %s", serial);

    return preverify_ok;
}

int set_cert(SSL_CTX  *ssl_ctx, const char *ca_file, const char *cert_file, const char *key_file){

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

    LSQ_INFO("ca-file: %s, cert_file: %s, key_file: %s", ca_file, cert_file, key_file);

    if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_file, NULL)) {
        LSQ_ERROR("Error loading ca certs");
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        LSQ_ERROR("Error loading client/server ca certs");
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        LSQ_ERROR("Error loading client/server ca key");
        return -1;
    }

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        LSQ_ERROR("check private key faile");
        return -1;
    }

    //SSL_CTX_set_default_verify_paths(ssl_ctx);

    return 1;
}

int
load_cert (struct lsquic_hash *certs, const char *ca_file, const char *cert_file, const char *key_file)
{
    int rv = -1;
    struct server_cert *cert = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *f = NULL;

    cert = calloc(1, sizeof(*cert));
    cert->ce_sni = strdup("echo");
    cert->ce_ssl_ctx = SSL_CTX_new(TLS_method());

    if (!cert->ce_ssl_ctx)
    {
        LSQ_ERROR("SSL_CTX_new failed");
        goto end;
    }

    if(set_cert(cert->ce_ssl_ctx, ca_file, cert_file, key_file) <= 0){
        LSQ_ERROR("set cert error");
        goto end;
    }

    SSL_CTX_set_alpn_select_cb(cert->ce_ssl_ctx, select_alpn, NULL);
    {
        const char *const s = getenv("LSQUIC_ENABLE_EARLY_DATA");
        if (!s || atoi(s))
            SSL_CTX_set_early_data_enabled(cert->ce_ssl_ctx, 1);
    }

    const int was = SSL_CTX_set_session_cache_mode(cert->ce_ssl_ctx, 1);
    LSQ_DEBUG("set SSL session cache mode to 1 (was: %d)", was);

    if (lsquic_hash_insert(certs, cert->ce_sni, strlen(cert->ce_sni), cert,
                                                            &cert->ce_hash_el))
        rv = 0;
    else
        LSQ_WARN("cannot insert cert for %s into hash table", cert->ce_sni);

  end:
    if (rv != 0)
    {   /* Error: free cert and its components */
        if (cert)
        {
            free(cert->ce_sni);
            free(cert);
        }
    }
    return rv;
}

struct ssl_ctx_st *
lookup_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED,
             const char *sni)
{
    struct lsquic_hash_elem *el;
    struct server_cert *server_cert;

    if (!cert_lu_ctx)
        return NULL;

    if (sni)
        el = lsquic_hash_find(cert_lu_ctx, sni, strlen(sni));
    else
    {
        LSQ_INFO("SNI is not set");
        el = lsquic_hash_first(cert_lu_ctx);
    }

    if (el)
    {
        server_cert = lsquic_hashelem_getdata(el);
        if (server_cert)
            return server_cert->ce_ssl_ctx;
    }

    return NULL;
}


void
delete_certs (struct lsquic_hash *certs)
{
    struct lsquic_hash_elem *el;
    struct server_cert *cert;

    for (el = lsquic_hash_first(certs); el; el = lsquic_hash_next(certs))
    {
        cert = lsquic_hashelem_getdata(el);
        SSL_CTX_free(cert->ce_ssl_ctx);
        free(cert->ce_sni);
        free(cert);
    }
    lsquic_hash_destroy(certs);
}
