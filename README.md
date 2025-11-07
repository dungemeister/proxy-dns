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
- Add threads to handle simultaneous
- Unit tests