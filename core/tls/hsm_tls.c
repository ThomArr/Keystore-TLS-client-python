#include <openssl/ssl.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static SSL_CTX *g_ctx = NULL;
static SSL *g_ssl = NULL;
static int g_fd = -1;

static char g_psk_hex[512]= "";
static char g_psk_identity[128] = "Client_identity";

static unsigned int hex_to_bytes(const char *hex, unsigned char *out, unsigned int max_out)
{
    unsigned int hex_len = strlen(hex);

    if (hex_len % 2 != 0) {
        return 0;
    }

    unsigned int out_len = hex_len / 2;

    if (out_len > max_out) {
        return 0;
    }

    for (unsigned int i = 0; i < out_len; i++) {
        unsigned int byte;

        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return 0;
        }

        out[i] = (unsigned char)byte;
    }

    return out_len;
}

static unsigned int psk_client_cb(
    SSL *ssl,
    const char *hint,
    char *identity,
    unsigned int max_identity_len,
    unsigned char *psk,
    unsigned int max_psk_len
)
{
    (void)ssl;
    (void)hint;

    if (strlen(g_psk_identity) + 1 > max_identity_len) {
        return 0;
    }

    strcpy(identity, g_psk_identity);

    return hex_to_bytes(g_psk_hex, psk, max_psk_len);
}

static int tcp_connect_hostport(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (fd < 0) {
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

void hsm_close(void)
{
    if (g_ssl != NULL) {
        SSL_shutdown(g_ssl);
        SSL_free(g_ssl);
        g_ssl = NULL;
    }

    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }

    if (g_ctx != NULL) {
        SSL_CTX_free(g_ctx);
        g_ctx = NULL;
    }
}

int hsm_connect(const char *host, const char *port, const char *sni, const char *psk_hex)
{
    hsm_close();

    if (host == NULL || port == NULL || sni == NULL || psk_hex == NULL) {
        return -1;
    }

    memset(g_psk_hex, 0, sizeof(g_psk_hex));

    if (strlen(psk_hex) >= sizeof(g_psk_hex)) {
        return -2;
    }

    strcpy(g_psk_hex, psk_hex);

    g_ctx = SSL_CTX_new(TLS_client_method());

    if (g_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return -3;
    }

    if (SSL_CTX_set_min_proto_version(g_ctx, TLS1_3_VERSION) != 1) {
        ERR_print_errors_fp(stderr);
        hsm_close();
        return -4;
    }

    if (SSL_CTX_set_max_proto_version(g_ctx, TLS1_3_VERSION) != 1) {
        ERR_print_errors_fp(stderr);
        hsm_close();
        return -5;
    }

    if (SSL_CTX_set_ciphersuites(g_ctx, "TLS_AES_128_CCM_SHA256") != 1) {
        ERR_print_errors_fp(stderr);
        hsm_close();
        return -6;
    }

    SSL_CTX_set_psk_client_callback(g_ctx, psk_client_cb);
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(g_ctx, SSL_OP_NO_TICKET);

    if (SSL_CTX_set1_groups_list(g_ctx, "P-256") != 1) {
        ERR_print_errors_fp(stderr);
        hsm_close();
        return -7;
    }

    g_fd = tcp_connect_hostport(host, port);

    if (g_fd < 0) {
        hsm_close();
        return -8;
    }

    g_ssl = SSL_new(g_ctx);

    if (g_ssl == NULL) {
        ERR_print_errors_fp(stderr);
        hsm_close();
        return -9;
    }

    SSL_set_fd(g_ssl, g_fd);
    SSL_set_tlsext_host_name(g_ssl, sni);

    if (SSL_connect(g_ssl) != 1) {
        ERR_print_errors_fp(stderr);
        hsm_close();
        return -10;
    }

    // fprintf(stderr, "[hsm_tls] connected host=%s port=%s sni=%s\n", host, port, sni);
    return 0;
}

int hsm_send(const unsigned char *data, int len)
{
    if (g_ssl == NULL || data == NULL || len <= 0) {
        return -1;
    }

    int written = SSL_write(g_ssl, data, len);

    if (written <= 0) {
        ERR_print_errors_fp(stderr);
        return -2;
    }

    return written;
}

int hsm_recv(unsigned char *buffer, int max_len)
{
    if (g_ssl == NULL || buffer == NULL || max_len <= 0) {
        return -1;
    }

    int read_len = SSL_read(g_ssl, buffer, max_len);

    if (read_len <= 0) {
        int err = SSL_get_error(g_ssl, read_len);

        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }

        ERR_print_errors_fp(stderr);
        return -2;
    }

    return read_len;
}