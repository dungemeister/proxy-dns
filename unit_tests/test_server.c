#include "../proxy-dns.h"

#define TEST_DEBUG(msg, ...) printf("%s"msg, __func__ , ##__VA_ARGS__)

void test_apply_default_config(){
    TEST_DEBUG(":\n");
    DnsServer_t proxy_server = {0};

    pd_apply_default_config(&proxy_server.conf);
    assert (proxy_server.conf.local_ip == ip_to_uint32(CONFIG_LOCAL_IP));
    assert (proxy_server.conf.local_port == CONFIG_LOCAL_PORT);
    assert (proxy_server.conf.upstream_ip == ip_to_uint32(CONFIG_UPSTREAM_IP));
    assert (proxy_server.conf.upstream_port == CONFIG_UPSTREAM_PORT);
    assert (proxy_server.conf.blacklist.capacity == 0);
    assert (proxy_server.conf.blacklist.size == 0);

    TEST_DEBUG(": PASS\n");
}

void test_server_init(){
    TEST_DEBUG(":\n");
    DnsServer_t proxy_server = {0};

    pd_apply_default_config(&proxy_server.conf);

    assert(0 == pd_init_dns_server(&proxy_server) && "Fail to init proxy dns server");
    pd_free_server(&proxy_server);
    TEST_DEBUG(": PASS\n");
}

void test_serve_server(){
    TEST_DEBUG(":\n");
    DnsServer_t proxy_server = {0};
    int serving_time = 5;
    pd_apply_default_config(&proxy_server.conf);

    assert(0 == pd_init_dns_server(&proxy_server) && "Fail to init proxy dns server");
    
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, pd_start_serving, (void*)&proxy_server);
    sleep(serving_time);
    
    pd_stop_serving(&proxy_server);
    pthread_join(server_thread, NULL);
    pd_free_server(&proxy_server);
    TEST_DEBUG(": PASS\n");
}

int main(int argc, char* argv[]){
    // test_apply_default_config();
    // test_server_init();
    test_serve_server();
    return 0;
}