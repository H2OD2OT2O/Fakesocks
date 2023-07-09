#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

char* resolve_hostname(const char* hostname) {
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET_ADDRSTRLEN];
    char* ip = NULL;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // 只解析IPv4地址
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void* addr;
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
        addr = &(ipv4->sin_addr);

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        ip = strdup(ipstr); // 复制字符串到新内存空间

        break; // 只返回第一个IP地址
    }

    freeaddrinfo(res);

    return ip;
}

int main() {
    const char* hostname = "127.0.0.1";
    char* ip = resolve_hostname(hostname);

    if (ip == NULL) {
        printf("Failed to resolve hostname %s\n", hostname);
    } else {
        printf("%s resolved to %s\n", hostname, ip);
        free(ip);
    }

    return 0;
}