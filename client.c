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
#include "utils.h"

#define BUF_SIZE 2048

extern pthread_mutex_t tls_mutex;

char *fakename, *servername;
unsigned short sport;
char key[32];
char iv[12] = {0};

void *relay(void *args)
{
    Args *info = (Args *)args;
    int from = info->from;
    int to = info->to;
    int n, ret;
    char *buf, *buf1;
    buf = malloc(BUF_SIZE);
    buf1 = malloc(BUF_SIZE);
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, info->buf, 256);
    // int data_len = 0;

    while (1)
    {
        if (info->c_or_r == 0)
        {
            n = recv(from, buf, BUF_SIZE - 16 - 5, 0);
            if (n <= 0)
            {
                goto end1;
            }
            ret = aes_256_gcm_encrypt(&ctx, buf, n, info->buf, 32, buf1 + 5 + 16, iv,
                                      sizeof(iv), buf1 + 5, 16);
            if (ret < 0)
                goto end1;
            buf1[0] = 0x17;
            buf1[1] = 0x03;
            buf1[2] = 0x03;
            *((unsigned short *)(buf1 + 3)) = htons(n + 16);
            n += 16 + 5;
        }
        else
        {
            n = recv_all(from, buf, 5, 0);
            if (n <= 0)
            {
                goto end1;
            }
            n = ntohs(*((unsigned short *)(buf + 3)));
            if (n > BUF_SIZE)
                goto end1;
            // data_len = n;
            n = recv_all(from, buf, n, 0);
            if (n <= 0)
            {
                goto end1;
            }
            ret = aes_256_gcm_decrypt(&ctx, buf + 16, n - 16, info->buf, 32, buf1, iv,
                                      sizeof(iv), buf, 16);
            if (ret < 0)
                goto end1;
            n -= 16;
        }
        pthread_mutex_lock(info->to_mutex);
        n = send(to, buf1, n, 0);
        pthread_mutex_unlock(info->to_mutex);
        if (n <= 0)
        {
            goto end1;
        }
    }
end1:
    free(buf);
    free(buf1);
    fprintf(stderr, "%ld:", time(NULL));
    perror("relay");
    mbedtls_gcm_free(&ctx);
    shutdown(to, SHUT_RDWR);
    pthread_exit(NULL);
}

void *handle_socks5(void *args)
{
    int sfd = *((int *)args);
    int sockfd;
    int n, ret;
    int none = 0;
    int ip_or_dns, dst_len, dst_port;
    unsigned char *buf;
    unsigned char random[32], random_key[32], dst[255];
    struct sockaddr_in addr, server_addr;
    struct timeval tv = {30, 0}; // 设置超时时间为30秒
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    buf = malloc(BUF_SIZE);
    if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        perror("setsockopt");
        close(sfd);
        free(buf);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }

    n = recv_all(sfd, buf, 2, 0);
    if (n <= 0 || buf[0] != 5)
    {
        printf("1 recv error or not socks5\n");
        close(sfd);
        free(buf);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }
    n = recv_all(sfd, buf, buf[1], 0);
    if (n <= 0)
    {
        printf("1 recv error\n");
        close(sfd);
        free(buf);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }
    for (int i = 0; i < n; i++)
    {
        if (buf[i] == 0)
        {
            none = 1;
            break;
        }
    }
    if (!none)
    {
        printf("2 method not supported\n");
        close(sfd);
        free(buf);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }

    buf[0] = 5;
    buf[1] = 0;

    ret = send(sfd, buf, 2, 0);
    if (ret == -1)
    {
        printf("3 send error\n");
        close(sfd);
        free(buf);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }

    n = recv_all(sfd, buf, 4, 0);
    if (n <= 0 || buf[0] != 5)
    {
        printf("4 recv error n:%d\n", n);
        perror("recv");
        close(sfd);
        free(buf);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }
    if (buf[1] == 1)
    {
        if (buf[3] == 1) // ipv4
        {
            n = recv_all(sfd, buf, 6, 0);
            if (n <= 0)
            {
                printf("4 recv error n:%d\n", n);
                perror("recv");
                close(sfd);
                free(buf);
                mbedtls_gcm_free(&ctx);
                pthread_exit(NULL);
            }
            memcpy(dst, buf, 4);
            dst_len = 4;
            ip_or_dns = 0;
            dst_port = ntohs(*((unsigned short *)(buf + 4)));
        }
        else if (buf[3] == 3)
        {
            n = recv_all(sfd, buf, 1, 0);
            if (n <= 0)
            {
                printf("4 recv error n:%d\n", n);
                perror("recv");
                close(sfd);
                free(buf);
                mbedtls_gcm_free(&ctx);
                pthread_exit(NULL);
            }
            int l = buf[0];
            n = recv_all(sfd, buf, l + 2, 0);
            if (n <= 0)
            {
                printf("4 recv error n:%d\n", n);
                perror("recv");
                close(sfd);
                free(buf);
                mbedtls_gcm_free(&ctx);
                pthread_exit(NULL);
            }
            memcpy(dst, buf, l);
            dst_len = l;
            dst_port = ntohs(*((unsigned short *)(buf + l)));
            ip_or_dns = 1;
        }
        else
        {               // ipv6 not supported
            buf[1] = 8; // address not supported
            ret = send(sfd, buf, 10, 0);
            printf("10 address not supported\n");
            close(sfd);
            free(buf);
            mbedtls_gcm_free(&ctx);
            pthread_exit(NULL);
        }
    }
    else
    {
        buf[1] = 7; // cmd not supported
        ret = send(sfd, buf, 10, 0);
        close(sfd);
        printf("11 cmd not supported\n");
        free(buf);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }

    // connect to server
    char *ip = resolve_hostname(servername);
    if (ip == NULL)
    { // resolve fail
        // host unreachable
        buf[0] = 5;
        buf[1] = 4;
        buf[2] = 0;
        buf[3] = 3;
        ret = send(sfd, buf, 10, 0);
        printf("7 resolv error\n");
        free(buf);
        free(ip);
        close(sfd);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(sport);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);
    free(ip);

    ret = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0)
    {
        perror("connect to ip");
        close(sockfd);
        buf[0] = 5;
        buf[1] = 5;
        buf[2] = 0;
        buf[3] = 1;
        ret = send(sfd, buf, 10, 0); // connect fail
        free(buf);
        close(sfd);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }
    buf[0] = 5;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 1;
    for (int i = 4; i < 10; i++)
        buf[i] = 0;
    // reply to client
    ret = send(sfd, buf, 10, 0);
    if (ret <= 0)
    {
        printf("6 reply error\n");
        close(sockfd);
        free(buf);
        close(sfd);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }

    // establish socks5
    if (send_socks5(sockfd, fakename, 443) != 0)
    {
        close(sockfd);
        free(buf);
        close(sfd);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }

    if (tls_handshake(sockfd, fakename, random) < 0)
    {
        close(sockfd);
        free(buf);
        close(sfd);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }
    // printf("Random:");
    // for (int i = 0; i < 32; i++)
    //     printf("%02X", random[i]);
    // printf("\n");

    // send application data

    buf[0] = 0x17;
    buf[1] = 0x03;
    buf[2] = 0x03;

    int *tmp = (int *)random_key;
    srand(time(NULL));
    for (int i = 0; i < 8; i++)
    {
        tmp[i] = rand();
    }
    *((unsigned short *)(buf + 3)) = htons(16 + 32 + 1 + ip_or_dns + dst_len + 2 + 32);
    memcpy(buf + 5 + 16, random, 32);
    buf[5 + 16 + 32] = ip_or_dns;
    if (ip_or_dns == 0)
    {
        memcpy(buf + 5 + 16 + 32 + 1, dst, 4);
        *((unsigned short *)(buf + 5 + 16 + 32 + 1 + 4)) = htons(dst_port);
        memcpy(buf + 5 + 16 + 32 + 1 + 4 + 2, random_key, 32);
    }
    else
    {
        buf[5 + 16 + 32 + 1] = dst_len;
        memcpy(buf + 5 + 16 + 32 + 1 + 1, dst, dst_len);
        *((unsigned short *)(buf + 5 + 16 + 32 + 1 + 1 + dst_len)) = htons(dst_port);
        memcpy(buf + 5 + 16 + 32 + 1 + 1 + dst_len + 2, random_key, 32);
    }

    unsigned char *buf1 = malloc(BUF_SIZE);

    aes_256_gcm_encrypt(&ctx, buf + 5 + 16, 32 + 1 + ip_or_dns + dst_len + 2 + 32,
                        key, 32,
                        buf1, iv, 12,
                        buf + 5, 16);
    memcpy(buf + 5 + 16, buf1, 32 + 1 + ip_or_dns + dst_len + 2 + 32);
    free(buf1);

    ret = send(sockfd, buf, 5 + 16 + 32 + 1 + ip_or_dns + dst_len + 2 + 32, 0);
    // printf("Buf:");
    // for (int i = 0; i < 32; i++)
    //     printf("%02X", buf[i]);
    // printf("\n");
    if (ret <= 0)
    {
        printf("send application error\n");
        close(sockfd);
        free(buf);
        close(sfd);
        mbedtls_gcm_free(&ctx);
        pthread_exit(NULL);
    }

    free(buf);
    pthread_t pid[2];
    pthread_mutex_t cli, ser;
    pthread_mutex_init(&cli, NULL);
    pthread_mutex_init(&ser, NULL);
    Args c2r = {sfd, sockfd, &cli, &ser, 0, random_key}, r2c = {sockfd, sfd, &ser, &cli, 1, random_key};
    pthread_create(&pid[0], NULL, relay, &c2r);
    pthread_create(&pid[1], NULL, relay, &r2c);
    pthread_join(pid[0], NULL);
    pthread_join(pid[1], NULL);
    pthread_mutex_destroy(&cli);
    pthread_mutex_destroy(&ser);
    close(sfd);
    close(sockfd);
    mbedtls_gcm_free(&ctx);
    printf("exit\n");
}

int main(int argc, char *argv[])
{
    int ret, listen_fd, conn_fd[100], idx = 0;
    const char *bind_addr = NULL;
    const char *port = NULL;
    char buf[BUF_SIZE];
    pthread_t pid;

    pthread_mutex_init(&tls_mutex, NULL);

    // 解析命令行参数
    if (argc == 7)
    {
        bind_addr = argv[1];
        port = argv[2];
        servername = argv[3];
        sport = atoi(argv[4]);
        fakename = argv[5];
        int stl = strlen(argv[6]);
        for (int i = 0; i < 32; i++)
        {
            key[i] = argv[6][i % stl];
        }
    }
    else
    {
        printf("Usage: %s bind_addr port servername server_port fakename password\n", argv[0]);
        return -1;
    }

    // 创建侦听套接字
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        printf("socket failed: %s\n", strerror(errno));
        return -1;
    }

    struct sigaction sa;
    sa.sa_handler = sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL); // 设置 SIGPIPE 信号的处理函数

    // 绑定本地地址
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    inet_pton(AF_INET, bind_addr, &addr.sin_addr);
    ret = bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
    {
        printf("bind failed: %s\n", strerror(errno));
        close(listen_fd);
        return -1;
    }

    // 开始侦听
    ret = listen(listen_fd, 5);
    if (ret < 0)
    {
        printf("listen failed: %s\n", strerror(errno));
        close(listen_fd);
        return -1;
    }

    while (1)
    {
        // 接受客户端连接
        conn_fd[idx] = accept(listen_fd, NULL, NULL);
        if (conn_fd < 0)
        {
            printf("accept failed: %s\n", strerror(errno));
            continue;
        }
        pthread_create(&pid, NULL, handle_socks5, &conn_fd[idx]);
        pthread_detach(pid);
        ++idx;
        idx %= 100;
    }

    close(listen_fd);
    return 0;
}