#include <stdio.h>
#include <pthread.h>

void *thread_func(void *arg);

int count = 0;  // 共享变量

int main() {
    pthread_t t1, t2;
    pthread_mutex_t mutex;

    pthread_mutex_init(&mutex, NULL);  // 初始化互斥锁

    pthread_create(&t1, NULL, thread_func, &mutex);
    pthread_create(&t2, NULL, thread_func, &mutex);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pthread_mutex_destroy(&mutex);  // 销毁互斥锁

    printf("count = %d\n", count);

    return 0;
}

void *thread_func(void *arg) {
    pthread_mutex_t *mutex = arg;  // 将参数转换为互斥锁指针
    int i;
    for (i = 0; i < 100000; i++) {
        pthread_mutex_lock(mutex);  // 获取互斥锁
        count++;  // 访问共享变量
        pthread_mutex_unlock(mutex);  // 释放互斥锁
    }
    return NULL;
}