#include "../proxy-dns.h"

#define TEST_DEBUG(msg, ...) printf("%s"msg, __func__ , ##__VA_ARGS__)

void test_server_init(){
    TEST_DEBUG(":\n");
    DnsServer_t proxy_server = {0};

    apply_default_config(&proxy_server.conf);

    assert(0 == init_dns_server(&proxy_server) && "Fail to init proxy dns server");
    TEST_DEBUG(": PASS\n");
}

int main(int argc, char* argv[]){
    test_server_init();
    return 0;
}