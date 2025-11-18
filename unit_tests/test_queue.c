#include "../proxy-dns.h"

#define TEST_DEBUG(msg, ...) printf("%s"msg, __func__ , ##__VA_ARGS__)

void test_queue_init(){
    TEST_DEBUG(":\n");

    TaskQueue_t queue;
    assert(0 == init_queue(&queue));

    shutdown_queue(&queue);
    free_queue(&queue);

    TEST_DEBUG(": PASS\n");
}

void test_enqueue_task(){
    TEST_DEBUG(":\n");

    TaskQueue_t queue;
    assert(0 == init_queue(&queue));

    struct client_data task = {0};

    enqueue_task(&queue, task);
    assert(1 == get_queue_count(&queue));

    enqueue_task(&queue, task);
    assert(2 == get_queue_count(&queue));

    shutdown_queue(&queue);
    free_queue(&queue);

    TEST_DEBUG(": PASS\n");
}

void test_dequeue_task(){
    TEST_DEBUG(":\n");

    TaskQueue_t queue;
    assert(0 == init_queue(&queue));

    struct client_data task = {0};

    enqueue_task(&queue, task);
    assert(1 == get_queue_count(&queue));

    enqueue_task(&queue, task);
    assert(2 == get_queue_count(&queue));

    dequeue_task(&queue);
    assert(1 == get_queue_count(&queue));
    dequeue_task(&queue);
    assert(0 == get_queue_count(&queue));

    shutdown_queue(&queue);
    free_queue(&queue);

    TEST_DEBUG(": PASS\n");
}

int main(int argc, char* argv[]){
    test_queue_init();
    test_enqueue_task();
    test_dequeue_task();
    return 0;
}