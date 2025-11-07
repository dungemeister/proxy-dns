#include <stdio.h>
#include "proxy-dns.h"

#define ARG_SHIFT(argc, arg) (--(*(argc)) > 0 ? ((arg)++)[0] : (arg)[0])
    
int parse_args(int *argc, char** argv){
    if(*argc > 1){
        printf("\tEnter -help to use the application properly\n");
        return -1;
    }

    char* arg;
    while(*argc > 0){
        arg = ARG_SHIFT(argc, argv);
        printf("%s\n", arg);
    }
    return 0;
}

int main(int argc, char** argv){
    printf("Hello from proxy-dns\n");
    
    int res = 0;
    if((res = parse_args(&argc, argv)) != 0){
        return res;
    }

    const char* config_file = "proxy.config";
    DnsServer_t proxy_server = {0};
    
    //Parse proxy dns config file
    if((res = parse_config_file(&proxy_server, config_file)) < 0){
        return res;
    }

    //Create dns server
    if((res = create_dns_server(&proxy_server)) < 0){
        return res;
    }
    
    //Serve forever
    serve_proxy_dns(&proxy_server);

    //Clear resources
    proxy_dns_shutdown(&proxy_server);

    return 0;
}