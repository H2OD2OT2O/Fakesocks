#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_NAME "baidu.com"
#define SERVER_PORT 443
#define GET_REQUEST "GET / HTTP/1.1\r\nHost: baidu.com\r\n\r\n"

char *resolve_hostname(const char *);
int my_send_func(void *, const unsigned char *, size_t);
int my_recv_func(void *, unsigned char *, size_t);

void mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

int main()
{
    int ret, sockfd;
    struct sockaddr_in servaddr;
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

    // 创建TCP套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // 初始化服务器地址结构体
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    char *ip = resolve_hostname(SERVER_NAME);
    if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0)
    {
        perror("inet_pton error");
        free(ip);
        exit(EXIT_FAILURE);
    }
    free(ip);

    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect error");
        exit(EXIT_FAILURE);
    }

    // 设置要验证的主机名
    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0)
    {
        fprintf(stderr, "mbedtls_ssl_set_hostname failed: %d\n", ret);
        goto exit;
    }

    // SSL上下文设置
    mbedtls_ssl_set_bio(&ssl, &sockfd, my_send_func, my_recv_func, NULL);

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

    ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME);
    if (ret != 0)
    {
        printf("Failed to set hostname.\n");
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &sockfd, my_send_func, my_recv_func, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf("Failed to perform SSL handshake.\n");
            goto exit;
        }
    }

    // Send the GET request
    size_t request_len = strlen(GET_REQUEST);
    while ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)GET_REQUEST, request_len)) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf("Failed to write to server.\n");
            goto exit;
        }
    }

    // Read the server's response
    unsigned char buf[1024];
    do
    {
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }
        if (ret <= 0)
        {
            break;
        }
        printf("%s", (char *)buf);
        break;
    } while (1);

    int real = sockfd;
    sockfd = 0;

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("Press any key to continue.\n");
    send(real, "Hello", 5, 0);
    getchar();
    close(real);
    return 0;
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

int my_send_func(void *ctx, const unsigned char *buf, size_t len)
{
    int ret = send(*(int *)ctx, buf, len, 0);
    // printf("send:%d\n", ret);
    return ret;
}

int my_recv_func(void *ctx, unsigned char *buf, size_t len)
{
    int ret = recv(*(int *)ctx, buf, len, 0);
    // printf("recv:%d\n", ret);
    return ret;
}