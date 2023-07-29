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
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define BUF_SIZE 2048

char key[32];
char iv[12] = {0};

void *relay(void *args)
{
    Args *info = (Args *)args;
    int from = info->from;
    int to = info->to;
    int n;
    char *buf, *plaintext;
    char random[32];
    buf = malloc(BUF_SIZE);
    plaintext = malloc(BUF_SIZE);
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);

    int buffer_size = 256 * 1024; // 缓冲区大小，单位为字节
    if (setsockopt(from, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0)
    {
        perror("setsockopt");
        goto end;
    }
    if (setsockopt(from, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0)
    {
        perror("setsockopt");
        goto end;
    }

    // detect fakesocks
    if (info->c_or_r == 0)
    {
        // client to remote

        n = recv_all(from, buf, 5, 0);
        if (n <= 0)
            goto end;
        // pthread_mutex_lock(info->to_mutex);
        n = send(to, buf, n, 0);
        // pthread_mutex_unlock(info->to_mutex);
        if (n <= 0)
        {
            goto end;
        }
        // check for tls handshake
        if (buf[0] != 0x16)
        {
            goto normal_relay;
        }
        n = ntohs(*((unsigned short *)(buf + 3)));
        if (n > 1500)
        {
            goto normal_relay;
        }
        n = recv_all(from, buf, n, 0);
        if (n <= 0)
            goto end;
        // pthread_mutex_lock(info->to_mutex);
        n = send(to, buf, n, 0);
        // pthread_mutex_unlock(info->to_mutex);
        if (n <= 0)
        {
            goto end;
        }
        // check for client hello
        if (buf[0] != 0x1)
        {
            goto normal_relay;
        }
        memcpy(random, buf + 6, 32);

        // wait for application data
        while (1)
        {
            n = recv_all(from, buf, 5, 0);
            if (n <= 0)
                goto end;
            // check for tls data
            if (buf[0] != 0x17)
            {
                n = ntohs(*((unsigned short *)(buf + 3)));
                if (n > 1500)
                {
                    // pthread_mutex_lock(info->to_mutex);
                    n = send(to, buf, 5, 0);
                    // pthread_mutex_unlock(info->to_mutex);
                    if (n <= 0)
                    {
                        goto end;
                    }
                    goto normal_relay;
                }
                n = recv_all(from, buf + 5, n, 0);
                if (n <= 0)
                    goto end;
                // pthread_mutex_lock(info->to_mutex);
                n = send(to, buf, n + 5, 0);
                // pthread_mutex_unlock(info->to_mutex);
                if (n <= 0)
                {
                    goto end;
                }
                continue;
            }
            n = ntohs(*((unsigned short *)(buf + 3)));
            if (n > 1500)
            {
                // pthread_mutex_lock(info->to_mutex);
                n = send(to, buf, 5, 0);
                // pthread_mutex_unlock(info->to_mutex);
                if (n <= 0)
                {
                    goto end;
                }
                goto normal_relay;
            }
            n = recv_all(from, buf + 5, n, 0);
            if (n <= 0)
                goto end;

            // try to decrypt
            if (n <= 16)
            {
                // pthread_mutex_lock(info->to_mutex);
                n = send(to, buf, n + 5, 0);
                // pthread_mutex_unlock(info->to_mutex);
                if (n <= 0)
                {
                    goto end;
                }
                goto normal_relay;
            }
            int ret = aes_256_gcm_decrypt(&ctx, buf + 5 + 16, n - 16,
                                          key, 32,
                                          plaintext, iv, 12,
                                          buf + 5, 16);
            // int ret = -1;
            if (info->buf[1] != 1 || ret != 0 || memcmp(plaintext, random, 32) != 0)
            {
                // pthread_mutex_lock(info->to_mutex);
                n = send(to, buf, n + 5, 0);
                // pthread_mutex_unlock(info->to_mutex);
                if (n <= 0)
                {
                    goto end;
                }
                goto normal_relay;
            }
            memcpy(info->buf, plaintext + 32, n - 16 - 32);
            printf("Fakesocks detected!\n");
            shutdown(to, SHUT_RDWR);
            goto end;
        }
    }
    else
    {
        // fake server to client

        n = recv_all(from, buf, 5, 0);
        if (n <= 0)
            goto end;
        // pthread_mutex_lock(info->to_mutex);
        n = send(to, buf, n, 0);
        // pthread_mutex_unlock(info->to_mutex);
        if (n <= 0)
        {
            goto end;
        }
        // check for tls handshake
        if (buf[0] != 0x16)
        {
            goto normal_relay;
        }
        n = ntohs(*((unsigned short *)(buf + 3)));
        if (n > 1500)
        {
            goto normal_relay;
        }
        n = recv_all(from, buf, n, 0);
        if (n <= 0)
            goto end;
        // pthread_mutex_lock(info->to_mutex);
        n = send(to, buf, n, 0);
        // pthread_mutex_unlock(info->to_mutex);
        if (n <= 0)
        {
            goto end;
        }
        // check for server hello
        if (buf[0] != 0x2)
        {
            goto normal_relay;
        }

        // wait for new session ticket
        while (1)
        {
            n = recv_all(from, buf, 5, 0);
            if (n <= 0)
                goto end;
            // pthread_mutex_lock(info->to_mutex);
            n = send(to, buf, 5, 0);
            // pthread_mutex_unlock(info->to_mutex);
            if (n <= 0)
            {
                goto end;
            }
            // check for tls handeshake data
            if (buf[0] != 0x16)
            {
                goto normal_relay;
            }
            n = ntohs(*((unsigned short *)(buf + 3)));
            int target = n;
            int recieved = 0;
            while (recieved < target)
            {
                n = recv(from, buf, target - recieved > BUF_SIZE ? BUF_SIZE : target - recieved, 0);
                if (recieved == 0 && buf[0] == 0x4)
                    info->buf[1] = 1;
                recieved += n;
                // pthread_mutex_lock(info->to_mutex);
                n = send(to, buf, n, 0);
                // pthread_mutex_unlock(info->to_mutex);
                if (n <= 0)
                {
                    goto end;
                }
            }
        }
    }
normal_relay:
    while (1)
    {
        n = recv(from, buf, BUF_SIZE, 0);
        if (n <= 0)
        {
            goto end;
        }
        // pthread_mutex_lock(info->to_mutex);
        n = send(to, buf, n, 0);
        // pthread_mutex_unlock(info->to_mutex);
        if (n <= 0)
        {
            goto end;
        }
    }
end:
    free(buf);
    free(plaintext);
    fprintf(stderr, "%ld:", time(NULL));
    perror("relay");
    mbedtls_gcm_free(&ctx);
    pthread_exit(NULL);
}

void *real_relay(void *args)
{
    Args *info = (Args *)args;
    int from = info->from;
    int to = info->to;
    int n, ret;
    char *buf, *buf1;
    // int data_len = 0;
    buf = malloc(BUF_SIZE);
    buf1 = malloc(BUF_SIZE);
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, info->buf, 256);

    int buffer_size = 256 * 1024; // 缓冲区大小，单位为字节
    // if (setsockopt(from, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0)
    // {
    //     perror("setsockopt");
    //     goto end1;
    // }
    // if (setsockopt(from, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0)
    // {
    //     perror("setsockopt");
    //     goto end1;
    // }

    while (1)
    {
        if (info->c_or_r == 0)
        {
            n = recv_all(from, buf, 5, 0);
            if (n <= 0)
            {
                goto end1;
            }
            n = ntohs(*((unsigned short *)(buf + 3)));
            if (n > BUF_SIZE)
                // data_len = n;
                goto end1;
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
        else
        {
            n = recv(from, buf, BUF_SIZE - 5 - 16, 0);
            if (n <= 0)
            {
                goto end1;
            }
            ret = aes_256_gcm_encrypt(&ctx, buf, n, info->buf, 32, buf1 + 16 + 5, iv, sizeof(iv), buf1 + 5, 16);
            if (ret < 0)
                goto end1;
            buf1[0] = 0x17;
            buf1[1] = 0x03;
            buf1[2] = 0x03;
            *((unsigned short *)(buf1 + 3)) = htons(n + 16);
            n += 16 + 5;
        }
        // pthread_mutex_lock(info->to_mutex);
        n = send(to, buf1, n, 0);
        // pthread_mutex_unlock(info->to_mutex);
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
    unsigned char *buf;
    struct timeval tv = {30, 0}; // 设置超时时间为30秒
    buf = malloc(BUF_SIZE);
    if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        perror("setsockopt");
        close(sfd);
        free(buf);
        pthread_exit(NULL);
    }

    n = recv_all(sfd, buf, 2, 0);
    if (n <= 0 || buf[0] != 5)
    {
        printf("1 recv error or not socks5\n");
        close(sfd);
        free(buf);
        pthread_exit(NULL);
    }
    n = recv_all(sfd, buf, buf[1], 0);
    if (n <= 0)
    {
        printf("1 recv error\n");
        close(sfd);
        free(buf);
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
        pthread_exit(NULL);
    }

    n = recv_all(sfd, buf, 4, 0);
    if (n <= 0 || buf[0] != 5)
    {
        printf("4 recv error n:%d\n", n);
        perror("recv");
        close(sfd);
        free(buf);
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
                pthread_exit(NULL);
            }
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            addr.sin_family = AF_INET;
            addr.sin_port = *((unsigned short *)(buf + 4));
            addr.sin_addr.s_addr = *((unsigned int *)buf);
            ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
            if (ret < 0)
            {
                printf("5 connect to %08X:%d error\n", ntohl(addr.sin_addr.s_addr), ntohs(addr.sin_port));
                perror("connect to ip");
                close(sockfd);
                buf[0] = 5;
                buf[1] = 5;
                buf[2] = 0;
                buf[3] = 1;
                ret = send(sfd, buf, 10, 0); // connect fail
                free(buf);
                close(sfd);
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
                pthread_exit(NULL);
            }
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
                pthread_exit(NULL);
            }
            int l = buf[0];
            char *add = malloc(l + 1);
            n = recv_all(sfd, buf, l + 2, 0);
            if (n <= 0)
            {
                printf("4 recv error n:%d\n", n);
                perror("recv");
                close(sfd);
                free(add);
                free(buf);
                pthread_exit(NULL);
            }
            memcpy(add, buf, l);
            add[l] = 0;
            printf("n:%d,add:%s\n", n, add);
            char *ip = resolve_hostname(add);
            free(add);
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
                pthread_exit(NULL);
            }

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            addr.sin_family = AF_INET;
            addr.sin_port = *((unsigned short *)(buf + l));
            inet_pton(AF_INET, ip, &addr.sin_addr);
            free(ip);
            ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
            if (ret < 0)
            {
                close(sockfd);
                buf[0] = 5;
                buf[1] = 5;
                buf[2] = 0;
                buf[3] = 3;
                ret = send(sfd, buf, 10, 0); // connect fail
                free(buf);
                close(sfd);
                printf("8 connect to remote error\n");
                pthread_exit(NULL);
            }
            buf[0] = 5;
            buf[1] = 0;
            buf[2] = 0;
            buf[3] = 3;
            for (int i = 4; i < 10; i++)
                buf[i] = 0;
            // reply to client
            ret = send(sfd, buf, 10, 0);
            if (ret <= 0)
            {
                printf("9 reply error\n");
                close(sockfd);
                free(buf);
                close(sfd);
                pthread_exit(NULL);
            }
        }
        else
        {               // ipv6 not supported
            buf[1] = 8; // address not supported
            ret = send(sfd, buf, 10, 0);
            printf("10 address not supported\n");
            close(sfd);
            free(buf);
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
        pthread_exit(NULL);
    }
    free(buf);
    pthread_t pid[2];
    pthread_mutex_t cli, ser;
    signed char *real_info;
    real_info = malloc(BUF_SIZE);
    real_info[0] = -1;
    real_info[1] = 0;
    pthread_mutex_init(&cli, NULL);
    pthread_mutex_init(&ser, NULL);
    Args c2r = {sfd, sockfd, &cli, &ser, 0, real_info}, r2c = {sockfd, sfd, &ser, &cli, 1, real_info};
    pthread_create(&pid[0], NULL, relay, &c2r);
    pthread_create(&pid[1], NULL, relay, &r2c);
    pthread_join(pid[0], NULL);
    pthread_join(pid[1], NULL);
    char *random_key;
    if (real_info[0] != -1)
    {
        close(sockfd);
        // printf("Real info:");
        // for (int i = 0; i < 32; i++)
        //     printf("%02x", (unsigned char)real_info[i]);
        // ip
        if (real_info[0] == 0)
        {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            addr.sin_family = AF_INET;
            addr.sin_port = *((unsigned short *)(real_info + 1 + 4));
            addr.sin_addr.s_addr = *((unsigned int *)real_info + 1);
            ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
            if (ret < 0)
            {
                printf("connect to %08X:%d error\n", ntohl(addr.sin_addr.s_addr), ntohs(addr.sin_port));
                perror("connect to ip");
                close(sockfd);
                close(sfd);
                goto exit;
            }
            random_key = real_info + 1 + 4 + 2;
        }
        // domain
        else if (real_info[0] == 1)
        {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            sockfd = socket(AF_INET, SOCK_STREAM, 0);

            int l = (unsigned char)real_info[1];
            char *add = malloc(l + 1);
            memcpy(add, real_info + 2, l);
            add[l] = 0;
            char *ip = resolve_hostname(add);
            free(add);
            if (ip == NULL)
            {
                printf("resolve %s error\n", ip);
                close(sockfd);
                close(sfd);
                goto exit;
            }
            addr.sin_family = AF_INET;
            addr.sin_port = *((unsigned short *)(real_info + 2 + l));
            inet_pton(AF_INET, ip, &addr.sin_addr);
            free(ip);
            ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
            if (ret < 0)
            {
                printf("connect to %08X:%d error\n", ntohl(addr.sin_addr.s_addr), ntohs(addr.sin_port));
                perror("connect to ip");
                close(sockfd);
                close(sfd);
                goto exit;
            }
            random_key = real_info + 1 + 1 + l + 2;
        }
        // connection established:sockfd
        Args r_c2r = {sfd, sockfd, &cli, &ser, 0, random_key}, r_r2c = {sockfd, sfd, &ser, &cli, 1, random_key};
        pthread_create(&pid[0], NULL, real_relay, &r_c2r);
        pthread_create(&pid[1], NULL, real_relay, &r_r2c);
        pthread_join(pid[0], NULL);
        pthread_join(pid[1], NULL);
        close(sfd);
        close(sockfd);
    }
    else
    {
        close(sfd);
        close(sockfd);
    }
exit:
    pthread_mutex_destroy(&cli);
    pthread_mutex_destroy(&ser);
    free(real_info);
    printf("exit\n");
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    int ret, listen_fd, conn_fd[100], idx = 0;
    const char *bind_addr = NULL;
    const char *port = NULL;
    char buf[BUF_SIZE];
    pthread_t pid;

    // 解析命令行参数
    if (argc == 4)
    {
        bind_addr = argv[1];
        port = argv[2];
        int stl = strlen(argv[3]);
        for (int i = 0; i < 32; i++)
        {
            key[i] = argv[3][i % stl];
        }
    }
    else
    {
        printf("Usage: %s bind_addr port password\n", argv[0]);
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