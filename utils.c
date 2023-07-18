#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include <mbedtls/debug.h>

char *tmp_buf;
pthread_mutex_t tls_mutex;

void sigpipe_handler(int sig)
{
    time_t t = time(NULL);
    fprintf(stderr, "%ld:Received SIGPIPE signal, ignore it.\n", t);
}

void mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

int my_send_func(void *ctx, const unsigned char *buf, size_t len)
{
    int ret = send(*(int *)ctx, buf, len, 0);
    if (buf[0] == 0x16 && buf[5] == 0x1)
    {
        memcpy(tmp_buf, buf + 11, 32);
        pthread_mutex_unlock(&tls_mutex);
    }
    return ret;
}

int my_recv_func(void *ctx, unsigned char *buf, size_t len)
{
    int ret = recv(*(int *)ctx, buf, len, 0);
    // printf("recv:%d\n", ret);
    return ret;
}

char *resolve_hostname(const char *hostname)
{
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET_ADDRSTRLEN];
    char *ip = NULL;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // 只解析IPv4地址
    hints.ai_socktype = SOCK_STREAM;
    printf("Host:%s\n", hostname);

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        void *addr;
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        ip = strdup(ipstr); // 复制字符串到新内存空间

        break; // 只返回第一个IP地址
    }

    freeaddrinfo(res);

    return ip;
}

int recv_all(int sockfd, void *buf, size_t len, int flags)
{
    char *pbuf = (char *)buf;
    size_t total = 0;
    int ret;

    while (total < len)
    {
        ret = recv(sockfd, pbuf + total, len - total, flags);
        if (ret == -1)
        {
            /* Handle error */
            return -1;
        }
        else if (ret == 0)
        {
            /* Connection closed */
            return 0;
        }
        total += ret;
    }

    return total;
}

int aes_256_gcm_encrypt(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *output, unsigned char *iv, size_t iv_len,
                        unsigned char *tag, size_t tag_len)
{
    int ret;

    ret = mbedtls_gcm_crypt_and_tag(ctx, MBEDTLS_GCM_ENCRYPT, input_len, iv, iv_len, NULL, 0, input, output, tag_len, tag);

    return ret;
}

int aes_256_gcm_decrypt(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *output, const unsigned char *iv, size_t iv_len,
                        const unsigned char *tag, size_t tag_len)
{
    int ret;
    ret = mbedtls_gcm_auth_decrypt(ctx, input_len, iv, iv_len, NULL, 0, tag, tag_len, input, output);

    return ret;
}

int send_socks5(int s, char *hostname, int port)
{
    char *buf;
    int n;
    buf = malloc(1024);
    buf[0] = 5;
    buf[1] = 2;
    buf[2] = 0;
    buf[3] = 1;
    if (send(s, buf, 4, 0) < 0)
    {
        fprintf(stderr, "Failed to connect to socks5 server.\n");
        return -1;
    }
    n = recv_all(s, buf, 2, 0);
    if (n <= 0 || buf[0] != 5 || buf[1] != 0)
    {
        fprintf(stderr, "Failed to negotiate with socks5 server.\n");
        return -1;
    }
    buf[0] = 5;
    buf[1] = 1;
    buf[2] = 0;
    buf[3] = 3;
    buf[4] = strlen(hostname);
    memcpy(buf + 5, hostname, strlen(hostname));
    *((unsigned short *)(buf + 5 + strlen(hostname))) = htons(port);

    if (send(s, buf, 5 + strlen(hostname) + 2, 0) < 0)
    {
        fprintf(stderr, "Failed to request to socks5 server.\n");
        return -1;
    }
    n = recv_all(s, buf, 10, 0);
    if (n <= 0 || buf[0] != 5 || buf[1] != 0)
    {
        fprintf(stderr, "Failed to receive response from socks5 server.\n");
        return -1;
    }
    free(buf);
    return 0;
}

int tls_handshake(int socks, char *hostname, char *random)
{
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0)
    {
        printf("Failed to seed random number generator.\n");
        goto exit;
    }

    // 设置要验证的主机名
    if ((ret = mbedtls_ssl_set_hostname(&ssl, hostname)) != 0)
    {
        fprintf(stderr, "mbedtls_ssl_set_hostname failed: %d\n", ret);
        goto exit;
    }

    // SSL上下文设置
    mbedtls_ssl_set_bio(&ssl, &socks, my_send_func, my_recv_func, NULL);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        printf("Failed to configure SSL.\n");
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, mbedtls_debug, stdout);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0)
    {
        printf("Failed to set up SSL.\n");
        goto exit;
    }

    // mbedtls_ssl_set_hs_cb(&ssl, my_handshake_callback, random);

    pthread_mutex_lock(&tls_mutex);
    tmp_buf = random;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf("Failed to perform SSL handshake.\n");
            pthread_mutex_unlock(&tls_mutex);
            goto exit;
        }
    }

    int real = socks;
    socks = 0;
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 0;

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return -1;
}
