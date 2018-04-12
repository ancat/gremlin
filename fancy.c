#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void* thread(void* c) {
    printf("cat \xf0\x9f\x90\xb1  is asleep!\n");
    sleep(10);
    printf("cat \xf0\x9f\x90\xb1  is awake! meoooooooow\n");
}

__attribute__((constructor))
void main() {
        pthread_t tid;
        pthread_create(&tid, NULL, thread, NULL);
        pthread_detach(tid);
}


