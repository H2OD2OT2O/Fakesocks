#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include <netdb.h>
#include <arpa/inet.h>

#define SERVER_ADDR "www.mi.com"
#define SERVER_PORT 443

char *resolve_hostname(const char *);
int my_send_func(void *, const unsigned char *, size_t);
int my_recv_func(void *, unsigned char *, size_t);

int main(void)
{
    int sockfd, ret;
    struct sockaddr_in servaddr;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "tls_client";

    int optval;
    socklen_t optlen = sizeof(optval);

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
    char *ip = resolve_hostname(SERVER_ADDR);
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

    // 初始化mbedtls库的上下文
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    printf("status:%d\n", getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen));

    // 随机数生成器初始化
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        fprintf(stderr, "mbedtls_ctr_drbg_seed failed: %d\n", ret);
        goto exit;
    }

    // SSL配置初始化
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        fprintf(stderr, "mbedtls_ssl_config_defaults failed: %d\n", ret);
        goto exit;
    }

    // 配置支持的TLS版本
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    // 设置要验证的主机名
    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_ADDR)) != 0)
    {
        fprintf(stderr, "mbedtls_ssl_set_hostname failed: %d\n", ret);
        goto exit;
    }
    printf("status:%d\n", getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen));

    // SSL上下文设置
    mbedtls_ssl_set_bio(&ssl, &sockfd, my_send_func, my_recv_func, NULL);

    printf("status:%d\n", getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen));

    // SSL握手
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            fprintf(stderr, "mbedtls_ssl_handshake failed: %d\n", ret);
            printf("status:%d\n", getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen));
            goto exit;
        }
    }

    // 进行TCP数据传输
    char buf[1024];
    while (1)
    {
        // 读取标准输入
        fgets(buf, sizeof(buf), stdin);

        // 发送数据
        ret = send(sockfd, buf, strlen(buf), 0);
        if (ret < 0)
        {
            perror("send error");
            goto exit;
        }

        // 接收数据
        ret = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (ret < 0)
        {
            perror("recv error");
            goto exit;
        }

        // 打印接收到的数据
        buf[ret] = '\0';
        printf("Received: %s", buf);
    }

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    close(sockfd);
    printf("status:%d\n", getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen));
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
    printf("send:%d\n", ret);
    return ret;
}

int my_recv_func(void *ctx, unsigned char *buf, size_t len)
{
    int ret = recv(*(int *)ctx, buf, len, 0);
    printf("recv:%d\n", ret);
    return ret;
}