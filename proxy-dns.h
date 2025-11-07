#ifndef _PROXY_DNS_H
#define _PROXY_DNS_H

#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/time.h>

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

#define DNS_HEADER_FLAGS_QR_MASK        (0x1L << DNS_HEADER_FLAGS_QR_OFFSET)
#define DNS_HEADER_FLAGS_OPCODE_MASK    (0xFL << DNS_HEADER_FLAGS_OPCODE_OFFSET)
#define DNS_HEADER_FLAGS_AA_MASK        (0x1L << DNS_HEADER_FLAGS_AA_OFFSET)
#define DNS_HEADER_FLAGS_TC_MASK        (0x1L << DNS_HEADER_FLAGS_TC_OFFSET)
#define DNS_HEADER_FLAGS_RD_MASK        (0x1L << DNS_HEADER_FLAGS_RD_OFFSET)
#define DNS_HEADER_FLAGS_RA_MASK        (0x1L << DNS_HEADER_FLAGS_RA_OFFSET)
#define DNS_HEADER_FLAGS_RES_MASK       (0x7L << DNS_HEADER_FLAGS_RES_OFFSET)
#define DNS_HEADER_FLAGS_RCODE_MASK     (0xFL << DNS_HEADER_FLAGS_RCODE_OFFSET)

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

typedef enum{
    BLACKLIST_DOMAIN_TYPE_NOT_BLACKLISTED = 0,
    BLACKLIST_DOMAIN_TYPE_REFUSED,
    BLACKLIST_DOMAIN_TYPE_NOT_FOUND,
    BLACKLIST_DOMAIN_TYPE_TRANSFORM,
}BlacklistDomainType_t;

typedef struct{
    BlacklistDomainType_t type;
    char name[256];
}BlacklistDomain_t;

typedef struct{
    BlacklistDomain_t domains[MAX_BLACKLIST_DOMAINS];
    int size;
    int capacity;
}DomainList_t;

typedef struct {
    uint32_t upstream_ip;
    int         upstream_port;
    uint32_t         local_ip;
    int         local_port;
    DomainList_t blacklist;
}DnsServerConfig_t;

typedef struct {
    DnsServerConfig_t conf;
    int sock_fd;
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
    char* qname;
    DnsQueryQuestionOpts_t opts;
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

#define DNS_QUESTION_SECTION_OFFSET (sizeof(DnsQueryHeader_t))

//Declaration functions as API
static int  parse_config_file(DnsServer_t* server, const char* config_file);
static int  create_dns_server(DnsServer_t* server);
static void serve_proxy_dns(DnsServer_t* server);
static void proxy_dns_shutdown(DnsServer_t* server);
//Declaration internal dunctions
static int  create_dns_socket(uint32_t addr, int port);
static void add_domain_to_blacklist(DomainList_t* blacklist, char* domain, BlacklistDomainType_t type);
static bool is_domain_blacklisted(DomainList_t* blacklist, char* domain);
static void trim_whitespace(char *str);
static uint32_t ip_to_uint32(const char* ip_address_str);
static void parse_question_section(char* buffer, char* domain);
static void build_blocked_response(char *buffer, int *len, char *query);
static int forward_to_upstream(char* query, int query_len, char* response, int response_buf_size, DnsServer_t* server);

//Implementation
static void add_domain_to_blacklist(DomainList_t* blacklist, char* domain, BlacklistDomainType_t type){
    if((blacklist->size + 1) > MAX_BLACKLIST_DOMAINS){
        fprintf(stderr, "Failed to add domain %s. Overflow\n", domain);
        return;
    }
    if(domain == NULL) {
        fprintf(stderr, "WARNING: domain name is %s\n", domain);
        return;
    }
    strcpy(blacklist->domains[blacklist->size].name, domain);
    blacklist->domains[blacklist->size++].type = type;
}

static bool is_domain_blacklisted(DomainList_t* blacklist, char* domain){
    for(int i = 0; i < blacklist->size; i++) {
        if(strstr(domain, blacklist->domains[i].name) != NULL) {
            return true;
        }
    }
    return false;
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

static unsigned int ip_to_uint32(const char* ip_address_str) {
    unsigned int ip_int = 0;
    char temp_ip_str[16]; // To hold IPv4 string
    strcpy(temp_ip_str, ip_address_str); // Create a mutable copy

    char* octet_str = strtok(temp_ip_str, ".");
    int octet_count = 0;

    while (octet_str != NULL && octet_count < 4) {
        unsigned int octet = atoi(octet_str);
        ip_int = (ip_int << 8) | octet;
        octet_str = strtok(NULL, ".");
        octet_count++;
    }

    return ip_int;
}

static BlacklistDomainType_t get_domain_type_from_string(char* type){
    if(type == NULL) return BLACKLIST_DOMAIN_TYPE_NOT_BLACKLISTED;

    if(strstr(type, BLACKLIST_TYPE_REFUSE_CHAR) != NULL){
        return BLACKLIST_DOMAIN_TYPE_REFUSED;
    }
    if(strstr(type, BLACKLIST_TYPE_NOT_FOUND_CHAR) != NULL){
        return BLACKLIST_DOMAIN_TYPE_NOT_FOUND;
    }
    printf("%s\n", type);
    return BLACKLIST_DOMAIN_TYPE_REFUSED;
}

static int parse_config_file(DnsServer_t* server, const char* config_file){
    FILE* cf = fopen(config_file, "r");
    if(cf == NULL){
        fprintf(stderr, "Fail to open config file\n");
        return -1;
    }

    char line[256];
    int line_number = 0;

    while(fgets(line, 256, cf)){
        line_number++;
        char* orig_line = strdup(line);
        (void)orig_line;
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

                printf("Upstream DNS: %s:%s\n", ip, port);
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
                        printf("%s\n", tokens[size]);
                        size++;
                    }
                }
                for(int i = 0; i < size; i++){
                                        
                    char *domain = strtok(tokens[i], "-");
                    char *action_or_ip = strtok(NULL, "-");

                    BlacklistDomainType_t type = get_domain_type_from_string(action_or_ip);
                    add_domain_to_blacklist(&server->conf.blacklist, domain, type);
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

                printf("Local DNS: %s:%s\n", ip, port);
                trim_whitespace(ip);
                server->conf.local_ip = ip_to_uint32(ip);
                trim_whitespace(port);
                server->conf.local_port = atoi(port);
            }
            token = strtok(NULL, " \t");
        }
    }
    return 0;
}

static int create_dns_server(DnsServer_t* server){
    DnsServerConfig_t* conf = &(server->conf);
    if((server->sock_fd = create_dns_socket(conf->local_ip, conf->local_port)) < 0){
        return -1;
    }

    return 0;
}

static void parse_question_section(char* buffer, char* domain){
    int offset = 0;
    int data_offset = 0;
    char data[256] = {0};
    while(buffer[offset] != 0){
        memcpy(&data[data_offset], &buffer[offset + 1], buffer[offset]);
        data_offset += buffer[offset];
        offset += buffer[offset] + 1;
        if(buffer[offset] != 0)
            data[data_offset++] = 0x2E;
    }
    memcpy(domain, data, data_offset + 1);
    DnsQueryQuestionOpts_t q_opts;
    q_opts.qtype =  ntohs(*(uint16_t*)&buffer[offset + 1]);
    q_opts.qclass = ntohs(*(uint16_t*)&buffer[offset + 1 + sizeof(q_opts.qtype)]);
    return;
}

static void build_blocked_response(char *buffer, int *len, char *query) {
    DnsQueryHeader_t* header = (DnsQueryHeader_t*)buffer;
    DnsQueryHeader_t* qheader = (DnsQueryHeader_t*)query;
    
    // Copy ID from query
    header->id = qheader->id;
    
    header->flags = htons(DNS_HEADER_FLAGS_QR_RESPONSE      | DNS_HEADER_FLAGS_OPCODE_STANDART_QUERY |
                          DNS_HEADER_FLAGS_RCODE_NXDOMAIN   | DNS_HEADER_FLAGS_AA_NON_AUTORITATIVE |
                          DNS_HEADER_FLAGS_RD_RECURSIVE     | DNS_HEADER_FLAGS_RA_RECURSIVE);
    
    // Counts
    header->qdcount = qheader->qdcount;
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    
    // Copy question section
    memcpy(buffer + sizeof(DnsQueryHeader_t), 
           query + sizeof(DnsQueryHeader_t), 
           *len - sizeof(DnsQueryHeader_t));
    
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

static void build_fail_response(char *buffer, int *len, char *query, BlacklistDomain_t domain){
    DnsQueryHeader_t* header = (DnsQueryHeader_t*)buffer;
    DnsQueryHeader_t* qheader = (DnsQueryHeader_t*)query;
    
    // Copy ID from query
    header->id = qheader->id;
    
    header->flags = htons(DNS_HEADER_FLAGS_QR_RESPONSE              | DNS_HEADER_FLAGS_OPCODE_STANDART_QUERY |
                          DNS_HEADER_FLAGS_RCODE_SERVER_FAILURE     | DNS_HEADER_FLAGS_AA_NON_AUTORITATIVE |
                          DNS_HEADER_FLAGS_RD_RECURSIVE             | DNS_HEADER_FLAGS_RA_RECURSIVE);
    
    // Counts
    header->qdcount = qheader->qdcount;
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    
    // Copy question section
    memcpy(buffer + sizeof(DnsQueryHeader_t), 
           query + sizeof(DnsQueryHeader_t), 
           *len - sizeof(DnsQueryHeader_t));
}

static void serve_proxy_dns(DnsServer_t* server){
    size_t client_buffer_size = 256;
    char buffer[client_buffer_size];

    char domain_name_buffer[256];
    char upstream_response[256];

    while(true){
        memset(buffer, 0x0, sizeof(buffer));
        
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int recv_len = recvfrom(server->sock_fd, buffer, sizeof(buffer), 0,
                               (struct sockaddr*)&client_addr, &client_len);
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        if(recv_len < 0){
            fprintf(stderr, "Recieve from client %s failed", client_ip);
            continue;
        }
        const DnsQueryHeader_t* header = (DnsQueryHeader_t*)buffer;
        
        void* question_section = buffer + DNS_QUESTION_SECTION_OFFSET;
        parse_question_section((char*)question_section, domain_name_buffer);
        
        printf("Query from %s for: %s\n", client_ip, domain_name_buffer);

        bool res = is_domain_blacklisted(&server->conf.blacklist, domain_name_buffer);
        if(res){
            printf("%s is in blacklist\n", domain_name_buffer);
            build_blocked_response(buffer, &recv_len, buffer);
            
            sendto(server->sock_fd, buffer, recv_len, 0,
                    (struct sockaddr*)&client_addr, client_len);
        }
        else{
            int response_len = forward_to_upstream(buffer, recv_len, upstream_response, sizeof(upstream_response), server);
                
            if(response_len > 0) {
                sendto(server->sock_fd, upstream_response, response_len, 0,
                        (struct sockaddr*)&client_addr, client_len);
                printf("Forwarded response for: %s (%d bytes)\n", domain_name_buffer, response_len);
            }
            else{
                build_fail_response(buffer, &recv_len, buffer, (BlacklistDomain_t){0});
                sendto(server->sock_fd, buffer, recv_len, 0,
                    (struct sockaddr*)&client_addr, client_len);
            }
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
#endif //_PROXY_DNS_H