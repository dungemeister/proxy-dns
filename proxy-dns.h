#ifndef _PROXY_DNS_H
#define _PROXY_DNS_H

#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/time.h>
#include <assert.h>
#include <pthread.h>

#define CONFIG_LOCAL_IP                 ("127.0.0.1")
#define CONFIG_LOCAL_PORT               (6969)
#define CONFIG_UPSTREAM_IP              ("9.9.9.9")
#define CONFIG_UPSTREAM_PORT            (53)

#define LINE_BUFFER_SIZE                (2048)
#define CLIENT_BUFFER_SIZE              (256)
#define DOMAIN_NAME_BUFFER_SIZE         (256)

#define MAX_BLACKLIST_DOMAINS           (100)
#define BLACKLIST_TYPE_REFUSE_CHAR      ("refuse")
#define BLACKLIST_TYPE_NOT_FOUND_CHAR   ("not_found")

#define DNS_HEADER_FLAGS_QR_OFFSET      (15)
#define DNS_HEADER_FLAGS_OPCODE_OFFSET  (11)
#define DNS_HEADER_FLAGS_AA_OFFSET      (10)
#define DNS_HEADER_FLAGS_TC_OFFSET      (9)
#define DNS_HEADER_FLAGS_RD_OFFSET      (8)
#define DNS_HEADER_FLAGS_RA_OFFSET      (7)
#define DNS_HEADER_FLAGS_RES_OFFSET     (4)
#define DNS_HEADER_FLAGS_RCODE_OFFSET   (0)

#define DNS_HEADER_FLAGS_QR_MASK        (0x1 << DNS_HEADER_FLAGS_QR_OFFSET)
#define DNS_HEADER_FLAGS_OPCODE_MASK    (0xF << DNS_HEADER_FLAGS_OPCODE_OFFSET)
#define DNS_HEADER_FLAGS_AA_MASK        (0x1 << DNS_HEADER_FLAGS_AA_OFFSET)
#define DNS_HEADER_FLAGS_TC_MASK        (0x1 << DNS_HEADER_FLAGS_TC_OFFSET)
#define DNS_HEADER_FLAGS_RD_MASK        (0x1 << DNS_HEADER_FLAGS_RD_OFFSET)
#define DNS_HEADER_FLAGS_RA_MASK        (0x1 << DNS_HEADER_FLAGS_RA_OFFSET)
#define DNS_HEADER_FLAGS_RES_MASK       (0x7 << DNS_HEADER_FLAGS_RES_OFFSET)
#define DNS_HEADER_FLAGS_RCODE_MASK     (0xF << DNS_HEADER_FLAGS_RCODE_OFFSET)

#define DNS_HEADER_FLAGS_QR_QUERY       ((0 << DNS_HEADER_FLAGS_QR_OFFSET) & DNS_HEADER_FLAGS_QR_MASK)
#define DNS_HEADER_FLAGS_QR_RESPONSE    ((1 << DNS_HEADER_FLAGS_QR_OFFSET) & DNS_HEADER_FLAGS_QR_MASK)

#define DNS_HEADER_FLAGS_OPCODE_STANDART_QUERY          ((0 << DNS_HEADER_FLAGS_OPCODE_OFFSET) & DNS_HEADER_FLAGS_OPCODE_MASK)
#define DNS_HEADER_FLAGS_OPCODE_INVERSE_QUERY           ((1 << DNS_HEADER_FLAGS_OPCODE_OFFSET) & DNS_HEADER_FLAGS_OPCODE_MASK)
#define DNS_HEADER_FLAGS_OPCODE_SERVER_STATUS_REQUEST   ((2 << DNS_HEADER_FLAGS_OPCODE_OFFSET) & DNS_HEADER_FLAGS_OPCODE_MASK)

#define DNS_HEADER_FLAGS_AA_NON_AUTORITATIVE    ((0 << DNS_HEADER_FLAGS_AA_OFFSET) & DNS_HEADER_FLAGS_AA_MASK)
#define DNS_HEADER_FLAGS_AA_AUTORITATIVE        ((1 << DNS_HEADER_FLAGS_AA_OFFSET) & DNS_HEADER_FLAGS_AA_MASK)

#define DNS_HEADER_FLAGS_TC_NOT_TRUNCATED       ((0 << DNS_HEADER_FLAGS_TC_OFFSET) & DNS_HEADER_FLAGS_TC_MASK)
#define DNS_HEADER_FLAGS_TC_TRUNCATED           ((1 << DNS_HEADER_FLAGS_TC_OFFSET) & DNS_HEADER_FLAGS_TC_MASK)

#define DNS_HEADER_FLAGS_RD_NOT_RECURSIVE       ((0 << DNS_HEADER_FLAGS_RD_OFFSET) & DNS_HEADER_FLAGS_RD_MASK)
#define DNS_HEADER_FLAGS_RD_RECURSIVE           ((1 << DNS_HEADER_FLAGS_RD_OFFSET) & DNS_HEADER_FLAGS_RD_MASK)

#define DNS_HEADER_FLAGS_RA_NOT_RECURSIVE       ((0 << DNS_HEADER_FLAGS_RA_OFFSET) & DNS_HEADER_FLAGS_RA_MASK)
#define DNS_HEADER_FLAGS_RA_RECURSIVE           ((1 << DNS_HEADER_FLAGS_RA_OFFSET) & DNS_HEADER_FLAGS_RA_MASK)

#define DNS_HEADER_FLAGS_RES                    ((0 << DNS_HEADER_FLAGS_RES_OFFSET) & DNS_HEADER_FLAGS_RES_MASK)

#define DNS_HEADER_FLAGS_RCODE_NO_ERROR                 ((0 << DNS_HEADER_FLAGS_RCODE_OFFSET) & DNS_HEADER_FLAGS_RCODE_MASK)
#define DNS_HEADER_FLAGS_RCODE_FORMAT_ERROR             ((1 << DNS_HEADER_FLAGS_RCODE_OFFSET) & DNS_HEADER_FLAGS_RCODE_MASK)
#define DNS_HEADER_FLAGS_RCODE_SERVER_FAILURE           ((2 << DNS_HEADER_FLAGS_RCODE_OFFSET) & DNS_HEADER_FLAGS_RCODE_MASK)
#define DNS_HEADER_FLAGS_RCODE_NXDOMAIN                 ((3 << DNS_HEADER_FLAGS_RCODE_OFFSET) & DNS_HEADER_FLAGS_RCODE_MASK)
#define DNS_HEADER_FLAGS_RCODE_NOT_SUPPORTED            ((4 << DNS_HEADER_FLAGS_RCODE_OFFSET) & DNS_HEADER_FLAGS_RCODE_MASK)
#define DNS_HEADER_FLAGS_RCODE_REFUSED                  ((5 << DNS_HEADER_FLAGS_RCODE_OFFSET) & DNS_HEADER_FLAGS_RCODE_MASK)

#define DNS_QUERY_TYPE_A            (1)
#define DNS_QUERY_TYPE_NAME_SERVER  (2)
#define DNS_QUERY_TYPE_CNAME        (5)
#define DNS_QUERY_TYPE_SOA          (6)
#define DNS_QUERY_TYPE_MX           (15)
#define DNS_QUERY_TYPE_TXT          (16)
#define DNS_QUERY_TYPE_AAAA         (28)
#define DNS_QUERY_TYPE_HTTPS        (65)

#define DNS_QUERY_CLASS_IN          (1)

typedef enum{
    BLACKLIST_DOMAIN_TYPE_NOT_BLACKLISTED = 0,
    BLACKLIST_DOMAIN_TYPE_REFUSED,
    BLACKLIST_DOMAIN_TYPE_NOT_FOUND,
    BLACKLIST_DOMAIN_TYPE_REDIRECT,
}BlacklistDomainType_t;

typedef struct{
    char                    name[256];
    BlacklistDomainType_t   type;
    uint32_t                redirect_ip;
}BlacklistDomain_t;

typedef struct{
    BlacklistDomain_t   domains[MAX_BLACKLIST_DOMAINS];
    int                 size;
    int                 capacity;
}DomainList_t;

typedef struct {
    uint32_t        upstream_ip;
    int             upstream_port;
    uint32_t        local_ip;
    int             local_port;
    DomainList_t    blacklist;
}DnsServerConfig_t;

typedef struct {
    DnsServerConfig_t   conf;
    int                 sock_fd;
}DnsServer_t;

#pragma pack(push, 1)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
}DnsQueryHeader_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint16_t qtype;
    uint16_t qclass;
}DnsQueryQuestionOpts_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    char*                   qname;
    DnsQueryQuestionOpts_t  opts;
}DnsQueryQuestionSection_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t length;
}DnsResponseOpts_t;
#pragma pack(pop)

typedef enum{
    CUSTOM_RESPONSE_REFUSE = 0,
    CUSTOM_RESPONSE_NOT_FOUND,
    CUSTOM_RESPONSE_READDRESSING,
    CUSTOM_RESPONSE_SERVER_FAILURE,
}CustomResponse_t;

#define DNS_QUESTION_SECTION_OFFSET (sizeof(DnsQueryHeader_t))
#define DNS_HEADER_SECTION_SIZE     DNS_QUESTION_SECTION_OFFSET


#define MAX_THREADS_SIZE (100)

typedef struct{
    struct client_data{
        struct sockaddr_in client_addr;
        socklen_t client_len;
        int client_sockfd;
        char buffer[CLIENT_BUFFER_SIZE];
        int data_len;
    }tasks[MAX_THREADS_SIZE];

    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int front, rear, count;
}TaskQueue_t;

typedef struct{
    TaskQueue_t* queue;
    DnsServer_t* server;
}WorketArgs_t;

//Declaration functions as API
static int  parse_config_file   (DnsServer_t* server, const char* config_file);
static int  create_dns_server   (DnsServer_t* server);
static void serve_proxy_dns     (DnsServer_t* server);
static void proxy_dns_shutdown  (DnsServer_t* server);
//Declaration internal dunctions
static void add_domain_to_blacklist (DomainList_t* blacklist, char* domain, BlacklistDomainType_t type, uint32_t redirect_ip);
static bool is_domain_blacklisted   (DomainList_t* blacklist, char* domain);

static int  create_dns_socket(uint32_t addr, int port);

static void     trim_whitespace (char *str);
static uint32_t ip_to_uint32    (const char* ip_address_str);

static void parse_question_section  (char* buffer, char* domain);
static void build_blocked_response  (char *buffer, int *len, char *query, BlacklistDomain_t type);
static void build_fail_response     (char *buffer, int *len, char *query, CustomResponse_t domain);
static int  forward_to_upstream     (char* query, int query_len, char* response, int response_buf_size, DnsServer_t* server);

static void init_queue(TaskQueue_t* queue);
static void run_pthread_pool(pthread_t* threads, size_t threads_size, void*(*func)(void*), WorketArgs_t* args);
static void enqueue_task(TaskQueue_t* queue, struct client_data task);
static struct client_data dequeue_task(TaskQueue_t* queue);
static void* thread_worker(void* arg);

//Implementation

static inline void print_config_local_dns_help(){
    printf("Usage:\n\tlocal-dns: 127.0.0.1:6969\nSpace between tokens is necessary");
}

static void print_config_params(DnsServerConfig_t* conf){
    
    struct in_addr ip = {0};
    
    ip.s_addr = htonl(conf->local_ip);
    printf("Local DNS: %s:%d\n", inet_ntoa(ip), conf->local_port);

    ip.s_addr = htonl(conf->upstream_ip);
    printf("Upstream DNS: %s:%d\n", inet_ntoa(ip), conf->upstream_port);
}

static void apply_default_config(DnsServerConfig_t* conf){
    conf->local_ip      = ip_to_uint32(CONFIG_LOCAL_IP);
    conf->local_port    = CONFIG_LOCAL_PORT;
    conf->upstream_ip   = ip_to_uint32(CONFIG_UPSTREAM_IP);
    conf->upstream_port = CONFIG_UPSTREAM_PORT;
}

static void add_domain_to_blacklist(DomainList_t* blacklist, char* domain, BlacklistDomainType_t type, uint32_t redirect_ip){
    if((blacklist->size + 1) > MAX_BLACKLIST_DOMAINS){
        fprintf(stderr, "Failed to add domain %s. Overflow\n", domain);
        return;
    }
    if(domain == NULL) {
        fprintf(stderr, "WARNING: domain name is %s\n", domain);
        return;
    }
    if(is_domain_blacklisted(blacklist, domain)){
        fprintf(stderr, "WARNING: domain '%s' already blacklisted. Ignored\n", domain);
        return;
    }
    strcpy(blacklist->domains[blacklist->size].name, domain);
    blacklist->domains[blacklist->size].redirect_ip = redirect_ip;
    blacklist->domains[blacklist->size++].type = type;
}

static bool is_domain_blacklisted(DomainList_t* blacklist, char* domain){
    if (domain == NULL) return false;

    for(int i = 0; i < blacklist->size; i++) {
        if(strstr(domain, blacklist->domains[i].name) != NULL) {
            return true;
        }
    }
    return false;
}

static BlacklistDomainType_t get_domain_type(DomainList_t* blacklist, char* domain){
    for(int i = 0; i < blacklist->size; i++) {
        if(strstr(domain, blacklist->domains[i].name) != NULL) {
            return blacklist->domains[i].type;
        }
    }
    return BLACKLIST_DOMAIN_TYPE_NOT_BLACKLISTED;
}

static BlacklistDomain_t get_domain_from_string(DomainList_t* blacklist, char* domain){
    for(int i = 0; i < blacklist->size; i++) {
        if(strstr(domain, blacklist->domains[i].name) != NULL) {
            return blacklist->domains[i];
        }
    }
    assert(false && "Cannot find domain in blacklist");
}

static char* get_domain_type_humanreadable(DomainList_t* blacklist, char* domain){
    BlacklistDomainType_t type = get_domain_type(blacklist, domain);
    BlacklistDomain_t dom = get_domain_from_string(blacklist, domain);
    switch (type)
    {
    case BLACKLIST_DOMAIN_TYPE_NOT_FOUND:
        return BLACKLIST_TYPE_NOT_FOUND_CHAR;
    
    case BLACKLIST_DOMAIN_TYPE_REFUSED:
        return BLACKLIST_TYPE_REFUSE_CHAR;
    case BLACKLIST_DOMAIN_TYPE_REDIRECT:
        struct in_addr ip = {dom.redirect_ip};
        return inet_ntoa(ip);
    default:
        return "Unknown";
    }
}

static void trim_whitespace(char *str) {
    char *end;
    if(str == NULL) return;
    // Remove spaces from beginning
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return;
    // Remove spaces from ending
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

static bool is_str_ip(const char* str){
    uint32_t ip = 0;
    return 1 == inet_pton(AF_INET, str, &ip);
}

static uint32_t ip_to_uint32(const char* ip_address_str) {
    if(is_str_ip(ip_address_str)){
        uint32_t ip = ntohl(inet_addr(ip_address_str));
        return ip;
    }
    assert(false && "Fail to convert ip string to uint32_t");
    return 0x0;
}

static BlacklistDomainType_t get_domain_type_from_string(char* type){
    if(type == NULL) return BLACKLIST_DOMAIN_TYPE_NOT_BLACKLISTED;

    if(strstr(type, BLACKLIST_TYPE_REFUSE_CHAR) != NULL){
        return BLACKLIST_DOMAIN_TYPE_REFUSED;
    }
    if(strstr(type, BLACKLIST_TYPE_NOT_FOUND_CHAR) != NULL){
        return BLACKLIST_DOMAIN_TYPE_NOT_FOUND;
    }
    if(is_str_ip(type)){
        return BLACKLIST_DOMAIN_TYPE_REDIRECT;
    }
    return BLACKLIST_DOMAIN_TYPE_NOT_BLACKLISTED;
}

static int parse_config_file(DnsServer_t* server, const char* config_file){
    FILE* cf = fopen(config_file, "r");
    if(cf == NULL){
        fprintf(stderr, "Fail to open config file '%s'\n", config_file);
        return -1;
    }

    char line[LINE_BUFFER_SIZE];
    int line_number = 0;

    while(fgets(line, LINE_BUFFER_SIZE, cf)){
        line_number++;
        if(line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        char *token = strtok(line, " \t");
        
        while (token != NULL) {
            if(strstr(token, "upstream-dns:") != NULL)
            {
                token = strtok(NULL, " \t");
                trim_whitespace(token);
                char* params = strtok(token, ":");
                char* ip = params;
                params = strtok(NULL, " :");
                char* port = params;

                assert(port != NULL && "Fail to parse upstream-dns port param");
                assert(ip != NULL   && "Fail to parse upstream-dns ip param");

                trim_whitespace(ip);
                server->conf.upstream_ip = ip_to_uint32(ip);
                trim_whitespace(port);
                server->conf.upstream_port = atoi(port);
            }
            else if(strstr(token, "blacklist:") != NULL)
            {
                char* tokens[MAX_BLACKLIST_DOMAINS];
                int size = 0;
                while(token != NULL && size < MAX_BLACKLIST_DOMAINS){
                    token = strtok(NULL, " \t");
                    if(token){
                        tokens[size] = token;
                        token = tokens[size];
                        size++;
                    }
                }
                for(int i = 0; i < size; i++){
                                        
                    char *domain = strtok(tokens[i], "-");
                    char *action_or_ip = strtok(NULL, "-");

                    uint32_t redirect_ip = 0x0;
                    BlacklistDomainType_t type = get_domain_type_from_string(action_or_ip);
                    if(type == BLACKLIST_DOMAIN_TYPE_REDIRECT) redirect_ip = ip_to_uint32(action_or_ip);
                        
                    add_domain_to_blacklist(&server->conf.blacklist, domain, type, redirect_ip);
                    printf("Added to blacklist: %s-%s\n", domain, action_or_ip);

                }
            }
            else if(strstr(token, "local-dns:") != NULL)
            {
                token = strtok(NULL, " \t");
                char* params = strtok(token, ":");
                char* ip = params;
                params = strtok(NULL, " :");
                char* port = params;

                assert(port != NULL && "Fail to parse local-dns port param");
                assert(ip != NULL && "Fail to parse local-dns ip param");

                trim_whitespace(ip);
                server->conf.local_ip = ip_to_uint32(ip);
                trim_whitespace(port);
                server->conf.local_port = atoi(port);

            }
            token = strtok(NULL, " \t");
        }
    }
    print_config_params(&server->conf);
    return 0;
}

static int create_dns_server(DnsServer_t* server){
    DnsServerConfig_t* conf = &(server->conf);
    if((server->sock_fd = create_dns_socket(conf->local_ip, conf->local_port)) < 0){
        return -1;
    }

    return 0;
}

static int get_qname_from_section_start(char* src_buffer, char* name_buf){
    int offset = 0;
    int data_offset = 0;
    while(src_buffer[offset] != 0){
        if(name_buf != NULL)
            memcpy(&name_buf[data_offset], &src_buffer[offset + 1], src_buffer[offset]);
        data_offset += src_buffer[offset];
        offset += src_buffer[offset] + 1;
        if(src_buffer[offset] != 0 && (name_buf != NULL))
            name_buf[data_offset++] = 0x2E;
    }
    return offset + 1;
}

static void parse_question_section(char* buffer, char* domain_buf){
    char data[256] = {0};
    int qname_size = get_qname_from_section_start(buffer, data);
    memcpy(domain_buf, data, qname_size + 1);
    //Query opts parsing
    DnsQueryQuestionOpts_t q_opts;
    q_opts.qtype =  ntohs(*(uint16_t*)&buffer[qname_size + 1]);
    q_opts.qclass = ntohs(*(uint16_t*)&buffer[qname_size + 1 + sizeof(q_opts.qtype)]);
    return;
}

static void build_readressed_response(char *buffer, int *len, char *query, BlacklistDomain_t domain){
    DnsQueryHeader_t *header  = (DnsQueryHeader_t*)buffer;
    DnsQueryHeader_t *qheader = (DnsQueryHeader_t*)query;
    
    // Set flags (QR=1, AA=1, RD=0, RA=0, RCODE=0)
    header->flags = htons(DNS_HEADER_FLAGS_QR_RESPONSE | DNS_HEADER_FLAGS_AA_AUTORITATIVE |
                          DNS_HEADER_FLAGS_RD_NOT_RECURSIVE | DNS_HEADER_FLAGS_RA_NOT_RECURSIVE |
                          DNS_HEADER_FLAGS_RCODE_NO_ERROR);
    
    // Set header values
    header->id = qheader->id;
    header->qdcount = qheader->qdcount;
    header->ancount = htons(1); // One answer
    header->nscount = 0;
    header->arcount = qheader->arcount;

    memcpy(buffer + sizeof(DnsQueryHeader_t), 
           query  + sizeof(DnsQueryHeader_t), 
           *len - DNS_HEADER_SECTION_SIZE);

    int query_qname_size = get_qname_from_section_start(buffer + sizeof(DnsQueryHeader_t), NULL);
    int query_section_size = query_qname_size + sizeof(DnsQueryQuestionOpts_t);
    int answer_size = 16;

    if(header->arcount != 0 || header->nscount != 0){
        //Gapping between query section and other sections to insert answer section
        memmove(buffer + sizeof(DnsQueryHeader_t) + query_section_size + answer_size,
                buffer + sizeof(DnsQueryHeader_t) + query_section_size,
                *len - (sizeof(DnsQueryHeader_t) + query_section_size));
    }

    assert(*len + answer_size < CLIENT_BUFFER_SIZE && "Size of input query more than allocated buffer size");
    // Allocate answer section buffer
    // char answer[answer_size];
    char* answer = buffer + sizeof(DnsQueryHeader_t) + query_section_size;
    
    // Pointer to domain name in question section (0xc00c)
    answer[0] = (char)(0x3 << 6); //Compressed label
    answer[1] = sizeof(DnsQueryHeader_t);
    
    DnsResponseOpts_t* ropts = (DnsResponseOpts_t*)&answer[2];
    // Type A (0x0001)
    ropts->rtype = htons(DNS_QUERY_TYPE_A);
    
    // Class IN (0x0001)
    ropts->rclass = htons(DNS_QUERY_CLASS_IN);
    
    // TTL (300 seconds = 0x0000012c)
    ropts->ttl = htonl(300);
    
    // RDATA length (4 bytes for IPv4)
    ropts->length = htons(sizeof(uint32_t));
    
    //IP redirect addr from blacklist domain entry
    *(uint32_t*)&answer[2 + sizeof(DnsResponseOpts_t)] = htonl(domain.redirect_ip);

    // memcpy(buffer + sizeof(DnsQueryHeader_t) + query_section_size, answer, answer_size);
    *len += answer_size;
}

static void build_blocked_response(char *buffer, int *len, char *query, BlacklistDomain_t domain) {
    if(domain.type == BLACKLIST_DOMAIN_TYPE_REFUSED)
        build_fail_response(buffer, len, query, CUSTOM_RESPONSE_REFUSE);
    else if(domain.type == BLACKLIST_DOMAIN_TYPE_NOT_FOUND)
        build_fail_response(buffer, len, query, CUSTOM_RESPONSE_NOT_FOUND);
    else if(domain.type == BLACKLIST_DOMAIN_TYPE_REDIRECT){
        // assert(false && "NOT IMPLEMENTED YET");
        build_readressed_response(buffer, len, query, domain);
    }
    
}

static int forward_to_upstream(char* query, int query_len, char* response, int response_buf_size, DnsServer_t* server) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    struct sockaddr_in upstream_addr;
    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(server->conf.upstream_port);
    // inet_pton(AF_INET, server->conf.upstream_ip, &upstream_addr.sin_addr);
    upstream_addr.sin_addr.s_addr = htonl(server->conf.upstream_ip);
    
    // Set timeout 1 sec
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Send to upstream DNS
    if(sendto(sock_fd, query, query_len, 0, 
              (struct sockaddr*)&upstream_addr, sizeof(upstream_addr)) < 0) {
        perror("Send to upstream failed");
        close(sock_fd);
        return -1;
    }
    
    // Receive response
    socklen_t addr_len = sizeof(upstream_addr);
    int response_len = recvfrom(sock_fd, response, response_buf_size, 0,
                               (struct sockaddr*)&upstream_addr, &addr_len);
    
    close(sock_fd);
    return response_len;
}

static void build_fail_response(char *buffer, int *len, char *query, CustomResponse_t resp_type){
    DnsQueryHeader_t* header = (DnsQueryHeader_t*)buffer;
    DnsQueryHeader_t* qheader = (DnsQueryHeader_t*)query;
    
    header->flags = qheader->flags;
    //Setting Response bit
    header->flags = htons(ntohs(header->flags) & ~DNS_HEADER_FLAGS_QR_MASK);
    header->flags = htons(ntohs(header->flags) | DNS_HEADER_FLAGS_QR_RESPONSE);

    //Setting Response Code 
    header->flags = htons(ntohs(header->flags) & ~DNS_HEADER_FLAGS_RCODE_MASK);
    if(resp_type == CUSTOM_RESPONSE_NOT_FOUND){
        header->flags |= htons(DNS_HEADER_FLAGS_RCODE_NXDOMAIN);
    }
    else if(resp_type == CUSTOM_RESPONSE_REFUSE){
        header->flags |= htons(DNS_HEADER_FLAGS_RCODE_REFUSED);
    }
    else if(resp_type == CUSTOM_RESPONSE_SERVER_FAILURE){
        header->flags |= htons(DNS_HEADER_FLAGS_RCODE_SERVER_FAILURE);
    }

    // Copy data from query
    header->id = qheader->id;
    header->qdcount = qheader->qdcount;
    header->ancount = qheader->ancount;
    header->nscount = qheader->nscount;
    header->arcount = qheader->arcount;
    
    // Copy question section
    memcpy(buffer + sizeof(DnsQueryHeader_t), 
           query + sizeof(DnsQueryHeader_t), 
           *len - sizeof(DnsQueryHeader_t));
}

static void serve_proxy_dns(DnsServer_t* server){
    char recv_buffer[CLIENT_BUFFER_SIZE];
    
    pthread_t threads[MAX_THREADS_SIZE];
    TaskQueue_t queue;
    init_queue(&queue);

    WorketArgs_t args = {0};
    args.queue = &queue;
    args.server = server;
    run_pthread_pool(threads, 10, thread_worker, &args);

    char domain_name_buffer[256];

    while(1){
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        int reuse_addr = 1;
        setsockopt(client_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

        if(client_sockfd < 0) {
            perror("Client socket creation failed");
            break;
        }

        int recv_len = recvfrom(server->sock_fd, recv_buffer, sizeof(recv_buffer), 0,
                               (struct sockaddr*)&client_addr, &client_len);

        if(recv_len <= 0){
            close(client_sockfd);
            continue;
        }
        struct sockaddr_in temp_addr;
        socklen_t temp_len = sizeof(temp_addr);
        temp_addr.sin_addr.s_addr = INADDR_ANY;
        temp_addr.sin_family = AF_INET;
        temp_addr.sin_port = htons(0);

        // printf("Received: %sFrom %s:%d\n", recv_buffer, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        if(bind(client_sockfd, (struct sockaddr*)&temp_addr, temp_len) == 0){

            struct client_data task;
            task.client_addr = client_addr;
            task.client_len = client_len;
            task.client_sockfd = client_sockfd;
            task.data_len = recv_len;
            memmove(task.buffer, recv_buffer, sizeof(recv_buffer));

            enqueue_task(&queue, task);
        }
        else{
            perror("Fail to bind socket to client addr");
            close(client_sockfd);
            sleep(1);
        }
    }
}

static void proxy_dns_shutdown(DnsServer_t* server){
    if(server->sock_fd >= 0){
        close(server->sock_fd);
    }
}

static int create_dns_socket(uint32_t addr, int port) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket fd creation failed");
        return -1;
    }
    
    int optval = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("socket setsockopt failed");
        close(sock_fd);
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(addr);
    server_addr.sin_port = htons(port);
    
    if (bind(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("socket bind failed");
        close(sock_fd);
        return -1;
    }
    
    return sock_fd;
}

static void init_queue(TaskQueue_t* queue){
    queue->count = 0;
    queue->front = 0;
    queue->rear = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);

}

static void enqueue_task(TaskQueue_t* queue, struct client_data task){
    pthread_mutex_lock(&queue->mutex);
    queue->tasks[queue->rear] = task;
    queue->rear = (queue->rear + 1) % MAX_THREADS_SIZE;
    queue->count++;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
}

static struct client_data dequeue_task(TaskQueue_t* queue){

    pthread_mutex_lock(&queue->mutex);
    if(queue->count == 0)
        pthread_cond_wait(&queue->cond, &queue->mutex);

    struct client_data task = {0};
    task = queue->tasks[queue->front];
    queue->front = (queue->front + 1) % MAX_THREADS_SIZE;
    queue->count--;

    pthread_mutex_unlock(&queue->mutex);

    return task;
}

static void* thread_worker(void* arg){
    WorketArgs_t* worket_args = arg;
    TaskQueue_t* queue = worket_args->queue;
    DnsServer_t* server = worket_args->server;

    // printf("Start worker. Queue: %p Server: %p\n", (void*)queue, (void*)server);
    char domain_name_buffer[DOMAIN_NAME_BUFFER_SIZE] = {0};
    char upstream_response[CLIENT_BUFFER_SIZE] = {0};

    while(1){
        struct client_data task = dequeue_task(queue);
        if(task.client_sockfd <= 0) continue;

        const DnsQueryHeader_t* header = (DnsQueryHeader_t*)task.buffer;
        (void)header;

        void* question_section = task.buffer + DNS_QUESTION_SECTION_OFFSET;
        parse_question_section((char*)question_section, domain_name_buffer);
        
        printf("DNS Query from %s:%d for: %s\n", inet_ntoa(task.client_addr.sin_addr), ntohs(task.client_addr.sin_port), domain_name_buffer);

        bool res = is_domain_blacklisted(&server->conf.blacklist, domain_name_buffer);
        if(res){
            char* humanreadable_type = get_domain_type_humanreadable(&server->conf.blacklist, domain_name_buffer);
            printf("%s is in blacklist: %s\n", domain_name_buffer, humanreadable_type);
            BlacklistDomain_t domain = get_domain_from_string(&server->conf.blacklist, domain_name_buffer);
            build_blocked_response(task.buffer, &task.data_len, task.buffer, domain);
            sendto(server->sock_fd, task.buffer, task.data_len, 0,
                    (struct sockaddr*)&task.client_addr, task.client_len);
        }
        else{
            int response_len = forward_to_upstream(task.buffer, task.data_len, upstream_response, sizeof(upstream_response), server);
                
            if(response_len > 0) {
                sendto(server->sock_fd, upstream_response, response_len, 0,
                        (struct sockaddr*)&task.client_addr, task.client_len);
                printf("Forwarded response for: %s (%d bytes)\n", domain_name_buffer, response_len);
            }
            else{
                build_fail_response(task.buffer, &task.data_len, task.buffer, CUSTOM_RESPONSE_SERVER_FAILURE);
                sendto(server->sock_fd, task.buffer, task.data_len, 0,
                    (struct sockaddr*)&task.client_addr, task.client_len);
            }
        }

        close(task.client_sockfd);
    }
    return NULL;
}

static void run_pthread_pool(pthread_t* threads, size_t threads_size, void*(*func)(void*), WorketArgs_t* args){
    int qty = (threads_size > MAX_THREADS_SIZE)? MAX_THREADS_SIZE : threads_size;
    for(int i = 0; i < qty; i++){
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        if(pthread_create(&threads[i], &attr, func, args) != 0){
            perror("Fail to create pthread");
        }
    }
}

#endif //_PROXY_DNS_H