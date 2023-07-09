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

#define BUF_SIZE 1024

void *relay(void *args)
{
    Args *info = (Args *)args;
    int from = info->from;
    int to = info->to;
    int n;
    char *buf;
    buf = malloc(BUF_SIZE);
    while (1)
    {
        n = recv(from, buf, BUF_SIZE, 0);
        if (n <= 0)
        {
            pthread_mutex_lock(info->from_mutex);
            close(from);
            pthread_mutex_unlock(info->from_mutex);
            close(to);
            free(buf);
            fprintf(stderr, "%ld:", time(NULL));
            perror("relay_recv");
            pthread_exit(NULL);
        }
        pthread_mutex_lock(info->to_mutex);
        n = send(to, buf, n, 0);
        pthread_mutex_unlock(info->to_mutex);
        if (n <= 0)
        {
            pthread_mutex_lock(info->from_mutex);
            close(from);
            pthread_mutex_unlock(info->from_mutex);
            close(to);
            free(buf);
            fprintf(stderr, "%ld:", time(NULL));
            perror("relay_send");
            pthread_exit(NULL);
        }
    }
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
    pthread_mutex_init(&cli, NULL);
    pthread_mutex_init(&ser, NULL);
    Args c2r = {sfd, sockfd, &cli, &ser, 0, NULL}, r2c = {sockfd, sfd, &ser, &cli, 0, NULL};
    pthread_create(&pid[0], NULL, relay, &c2r);
    pthread_create(&pid[1], NULL, relay, &r2c);
    pthread_join(pid[0], NULL);
    pthread_join(pid[1], NULL);
    pthread_mutex_destroy(&cli);
    pthread_mutex_destroy(&ser);
    printf("exit\n");
}

int main(int argc, char *argv[])
{
    int ret, listen_fd, conn_fd[100], idx = 0;
    const char *bind_addr = NULL;
    const char *port = NULL;
    char buf[BUF_SIZE];
    pthread_t pid;

    // 解析命令行参数
    if (argc == 3)
    {
        bind_addr = argv[1];
        port = argv[2];
    }
    else
    {
        printf("Usage: %s bind_addr port\n", argv[0]);
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