#include <signal.h>
#include <stdio.h>

void sigpipe_handler(int sig) {
    printf("Received SIGPIPE signal, ignore it.\n");
}

int main() {
    struct sigaction sa;
    sa.sa_handler = sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);  // 设置 SIGPIPE 信号的处理函数
    // ...
    while(1);
    return 0;
}