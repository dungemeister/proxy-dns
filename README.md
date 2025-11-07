# proxy-dns

One header file proxy-dns.h library. Configurable proxy-dns server.

# Description
    
Proxy DNS application with config file based on UDP datagrams.
App accepts blacklist from config file to manage desired actions to hostnames:
- refuse - to refuse query (RCODE=5 (Refused))
- not_found - to notify about name error (RCODE=3(Name Error))
- ip_address - to answer to query with desired IP (RCODE=0 (No Error))

Other posible RCODES:
- RCODE=2 (Server Failure) - upstream DNS timeout

# Usage
File main.c demonstrates basic use of the library.

1. It allocates DnsServer structure and config file string.

```c
//main.c
#include "proxy-dns.h"
// int main()
const char* config_file = "proxy.config";
DnsServer_t proxy_server = {};

```
2. Parsing config file

```c
// int main()
// ...
if((res = parse_config_file(&proxy_server, config_file)) < 0){
    return res;
}
```
3. Socket creation 

```c
// int main()
// ...
if((res = create_dns_server(&proxy_server)) < 0){
    return res;
}
```

4. Serving

```c
// int main()
// ...
serve_proxy_dns(&proxy_server);
```
5. Clearing resources

```c
// int main()
// ...
proxy_dns_shutdown(&proxy_server);
```

# Dependencies

Independent one header file library from scratch.

# Build
    To build project use:

    ```bash
        make build
    ```

    To clean project use:

    ```bash
        make clean
    ```

    To rebuild project use:
    
    ```bash
        make all
    ```

# WARNINGS
- Handling queries in single thread
- Necessary fields in config file: 'local-dns:', 'upstream-dns:', 'blacklist:'

# ERRATA
- Segfault with broken config
- Answer with desired IP from blacklist is broken    

# TODO
- Update config file and parsing for future features
- Add POSIX threads to handle simultaneous connections
- Unit tests
- Add default params for proxy server
- Add signals handling for app