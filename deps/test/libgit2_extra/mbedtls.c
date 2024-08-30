// https://github.com/mattnite/zig-libgit2
// hack around libgit2 mbedtls ssl config so that I can load in windows root
// certs, and for use in zfetch

#include "../libgit2/src/libgit2/streams/mbedtls.c"

typedef struct mbedtls_ssl_conf mbedtls_ssl_conf;
mbedtls_ssl_conf *git_mbedtls__get_ssl_conf() {
    return git__ssl_conf;
}

void git_mbedtls__insecure() {
    mbedtls_ssl_conf_authmode(git__ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
}

int git_mbedtls__set_cert_buf(const unsigned char *buf, size_t len) {
    mbedtls_x509_crt *cacert = git__malloc(sizeof(mbedtls_x509_crt));
    GIT_ERROR_CHECK_ALLOC(cacert);

    mbedtls_x509_crt_init(cacert);
    int ret = mbedtls_x509_crt_parse(cacert, buf, len);
    if (ret < 0) {
        char buf[512];
        mbedtls_x509_crt_free(cacert);
        git__free(cacert);
        mbedtls_strerror(ret, buf, sizeof(buf));
        git_error_set(GIT_ERROR_SSL, "failed to load CA certificates: %#04x - %s", ret, buf);
        return -1;
    }

    mbedtls_x509_crt_free(git__ssl_conf->ca_chain);
    git__free(git__ssl_conf->ca_chain);
    mbedtls_ssl_conf_ca_chain(git__ssl_conf, cacert, NULL);
    return 0;
}

static void my_debug( void *ctx, int level, const char *file, int line, const char *str ) { 
    ((void) level);
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx); 
}

void git_mbedtls__set_debug() {
    mbedtls_ssl_conf_dbg(&git__ssl_conf, my_debug, stdout);
}
