# proxy-dns

One header file proxy-dns.h linux only library. Configurable proxy-dns server.

# Description
    
Proxy DNS application with config file based on UDP datagrams.
App accepts blacklist from config file to manage desired actions to hostnames:
- refuse - to refuse query (RCODE=5 (Refused))
- not_found - to notify about name error (RCODE=3(Name Error))
- ip_address - to answer to query with desired IP (RCODE=0 (No Error))

Other posible RCODES:
- RCODE=2 (Server Failure) - upstream DNS timeout

# Dependencies

Dependencies: pthread

To build your app with current library link pthread library as linker flag:

```bash
-lpthread
```

# Build
To build project use:

```bash
    make proxy-dns
```

To clean project use:

```bash
    make clean
```

To rebuild project use:

```bash
    make rebuild
```

# Launch

Local IP and local port described in config file (proxy.config)

To Launch with default path to config file (proxy.config):

```txt

./build/proxy-dns
```

To Launch with desired config file run with arg:
```txt

./build/proxy-dns path_to_config
```


# Library usage
File main.c demonstrates basic use of the library.

1. It allocates DnsServer structure and config file string.

```c
//main.c
#include "proxy-dns.h"
const char* config_file = "proxy.config";
// int main()
DnsServer_t proxy_server = {};

```
2. Parsing config file. If it fails apply default config from defines

```c
// int main()
// ...
if((res = parse_config_file(&proxy_server, config_file)) < 0){
    apply_default_config(&proxy_server.conf);
}
```
3. Server initialization

```c
// int main()
// ...
if((res = init_dns_server(&proxy_server)) < 0){
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

# Config constrains
Default config name proxy.config. In addition set config path via arg[1].

Necessary fields:
- 'local-dns:'. The following space is required to separate tokens.
- 'upstream-dns:'. The following space is required to separate tokens.
- 'blacklist:'. The following space is required to separate tokens.

**Each field must occupy one line. The line size is limited by the allocated buffer**
### local-dns
Setting local proxy-dns IP address and port
field type - local-dns: IP:port
For example:
```text
    local-dns: 127.0.0.1:6969 
```
### upstream-dns
Setting upstream dns IP address and port
field type - upstream-dns: IP:port
For example:
```text
    upstream-dns: 9.9.9.9:53
```

### blacklist
Setting blacklist with domains and different actions for them.
Line limited by allocated buffer size. 
Actions:
- refuse - insert in header status REFUSE (RCODE=5)
- not_found - insert in header status NXDOMAIN (Name Error  RCODE=3)
- IP - building answer section with desired IP
Supports logical separation. Valid examples:

```text
blacklist: google.com-refuse ya.ru-not_found yandex.ru-10.10.10.10 github.com-refuse linkedin.com-not_found youtube.com-refuse
```

```text
blacklist: google.com-refuse github.com-refuse youtube.com-refuse 
blacklist: ya.ru-not_found linkedin.com-not_found
blacklist: yandex.ru-10.10.10.10
```

```text
blacklist: google.com-refuse
blacklist: ya.ru-not_found
blacklist: yandex.ru-10.10.10.10
blacklist: github.com-refuse
blacklist: linkedin.com-not_found
blacklist: youtube.com-refuse
...
```

# System testing environment
To prepare testing environment run test_env.sh script or create virtual environment and install pytest module by yourself with pip or wheel.
A utility dig is required for the tests to work correctly
```sh
python3 -m venv venv

source venv/bin/activate

pip install pytest psutil
```

# Testing
To run tests execute script run_tests.sh

Tested with util dig (DNS lookup utility)
**Test .config file must be named as associated function name in test_proxy-dns.py file**

### Domain from blacklist REFUSE type:

test_blacklist_refused in pytest env.
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_blacklist_refused.config
```

2.Running dig with domain name in blacklist with tag 'refuse':

```bash
    dig @127.0.0.1 -p 6969 google.com
```

Expected output status is REFUSED:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 5306
```

### Domain from blacklist NOT_FOUND type:

test_blacklist_not_found in pytest env
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_blacklist_not_found.config
```

2.Running dig with domain name in blacklist with tag 'not_found':

```bash
    dig @127.0.0.1 -p 6969 ya.ru
```

Expected output status is REFUSED:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 5306
```

### Domain from blacklist with READDRESSING type:

test_blacklist_readressing in pytest env
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_blacklist_readressing.config
```

2.Running dig with domain name in blacklist with readressing IP '10.10.10.10':

```bash
    dig @127.0.0.1 -p 6969 ya.ru
```

Expected output status is NOERROR:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5306
```

Expected IP from answer section is 10.10.10.10:

```bash
    yandex.ru.		300	IN	A	10.10.10.10
```

### Existed domain not from blacklist:

test_existed_domain in pytest env
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_existed_domain.config
```

2.Running dig with domain name not in blacklist 'github.com':

```bash
    dig @127.0.0.1 -p 6969 github.com
```

Expected output status is NOERROR:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5306
```

### Not existed domain not from blacklist:

test_not_existed_domain in pytest env
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_not_existed_domain.config
```

2.Running dig with domain name not in blacklist and with random name to forward to upstream dns 9.9.9.9:53:

```bash
    dig @127.0.0.1 -p 6969 googlerrob.com.123.123
```

Expected output status is NXDOMAIN:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 5306
```

### Not existed upstream DNS:

test_not_existed_upstream in pytest env
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_not_existed_upstream.config
```

2.Running dig with domain name not in blacklist 'github.com' to forward to not existed upstream dns 119.119.119.119:53:

```bash
    dig @127.0.0.1 -p 6969 github.com
```

Expected output status is SERVFAIL:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 5306
```

### Existed upstream DNS:

test_existed_upstream in pytest env
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_existed_upstream.config
```

2.Running dig with domain name not in blacklist 'github.com' to forward to existing upstream 9.9.9.9:53:

```bash
    dig @127.0.0.1 -p 6969 github.com
```

Expected output status is NOERROR:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5306
```

### Correct queries with huge blacklist:

test_correct_queries_with_huge_blacklist in pytest env
1.Running proxy-dns server with config:

```bash
    ./build/proxy-dns tests/test_existed_upstream.config
```

2.Running dig with domain name not in blacklist 'github.com' to compare parsing time with default timeouts for huge blacklist:

```bash
    dig @127.0.0.1 -p 6969 github.com
```

Expected output status is NOERROR:

```bash
 ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5306
```

# CONSTRAINS
- Tested only for Class IN queries
- Only IPv4 (Type A)
- Only userspace local ports > 1024

# WARNINGS
- Handling queries in multithread mode
- Necessary fields in config file: 'local-dns:', 'upstream-dns:', 'blacklist:'
- Broken trim_whitespaces function
- Limitted length of the input line buffer. Look at preprocessed variable LINE_BUFFER_SIZE.

# ERRATA
- Segfault with broken config
- ~~Answer with desired IP from blacklist is broken~~  

# TODO
- [x] ~~Update config file and parsing for future features~~
- [x] ~~Add POSIX threads to handle simultaneous connections~~
- [x] ~~Unit tests~~
- [x] ~~Add default params for proxy server~~
- [x] ~~Add signals handling for app~~
- [x] ~~Add checking domain name while appending in blacklist~~
- [x] ~~Add cache for requested domains~~
- [x] ~~Add programm args parsing~~
- [ ] Config hot reload
