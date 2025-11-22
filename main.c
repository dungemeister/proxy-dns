#include <stdio.h>

#define PROXY_DNS_IMPLEMENTATION
#include "proxy-dns.h"

#include <signal.h>

#define ARG_SHIFT(argc, arg) (--(*(argc)) > 0 ? ((arg)++)[0] : (arg)[0])

const char* config_file = "proxy.config";


int parse_args(int *argc, char** argv){
    char* program_path = ARG_SHIFT(argc, argv);
    (void)program_path;
    if(*argc > 1){
        
        fprintf(stderr, "ERROR: Correct App usage - proxy-dns <config_file> (optional) \n");
        exit(-1);
    }
    if(*argc == 1){
        char* new_config_file = ARG_SHIFT(argc, argv);
        config_file = new_config_file;
        printf("Config file: %s\n", new_config_file);
    }

    return 0;
}

void signal_handler(int sig){
    (void)sig;
    exit(-1);
}

int main(int argc, char** argv){
    printf("Hello from proxy-dns\n");

    int res = 0;
    if((res = parse_args(&argc, argv)) != 0){
        return res;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    DnsServer_t proxy_server = {0};
    
    //Parse proxy dns config file
    if((res = pd_parse_config_file(&proxy_server, config_file)) < 0){
        printf("Applying default settings\n");
        pd_apply_default_config(&proxy_server.conf);
        
    }

    //Create dns server
    if((res = pd_init_dns_server(&proxy_server)) < 0){
        return res;
    }
    
    //Serve forever
    pd_start_serving(&proxy_server);

    //Clear resources
    pd_free_server(&proxy_server);

    return 0;
}