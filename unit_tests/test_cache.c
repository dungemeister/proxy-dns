#include "../proxy-dns.h"

#define TEST_DEBUG(msg, ...) printf("%s"msg, __func__ , ##__VA_ARGS__)

const BlacklistDomain_t default_domain = {
    .name = "google.com",
    .redirect_ip = 0,
    .type = BLACKLIST_DOMAIN_TYPE_NOT_FOUND
};

DnsCacheEntry_t entry = {
    .valid = 1,
    .ttl = 300,
    .next = NULL,
    .resp_status = DNS_HEADER_FLAGS_RCODE_NO_ERROR,
    .response_len = 0,
    .timestamp = 0,
    .domain = default_domain,
};

void test_collision_cache(){
    TEST_DEBUG(":\n");
    DnsCacheTable_t cache;
    assert(0 == init_cache_table(&cache) && "FAIL: Fail to init cache table");

    add_cache_entry(&cache, &entry);
    assert(1 == get_cache_size(&cache) && "FAIL: Expected cache size 1");
    add_cache_entry(&cache, &entry);
    assert(2 == get_cache_size(&cache) && "FAIL: Expected cache size 2");
    
    free_cache_table(&cache);
    TEST_DEBUG(": PASS\n");
}

void test_free_cache(){
    TEST_DEBUG(":\n");
    DnsCacheTable_t cache;
    assert(0 == init_cache_table(&cache) && "FAIL: Fail to init cache table");

    add_cache_entry(&cache, &entry);

    free_cache_table(&cache);
    assert(0 == get_cache_size(&cache) && "FAIL: Expected cache size 0");

    pthread_rwlock_t* rwlock = get_cache_mutex(&cache);
    assert(0 == pthread_rwlock_rdlock(rwlock) && "FAIL: Expected cache correct rwlock lock");
    assert(0 == pthread_rwlock_unlock(rwlock) && "FAIL: Expected cache correct rwlock unlock");

    assert(NULL == get_cache_hash_table(&cache) && "FAIL: Expected cache hashtable ptr NULL");
    TEST_DEBUG(": PASS\n");
}

void test_remove_entry_cache(){
    TEST_DEBUG(":\n");
    DnsCacheTable_t cache;
    assert(0 == init_cache_table(&cache) && "FAIL: Fail to init cache table");

    assert(0 == add_cache_entry(&cache, &entry) && "FAIL: Cannot add entry to cache");
    assert(0 == add_cache_entry(&cache, &entry) && "FAIL: Cannot add entry to cache");
    assert(0 == add_cache_entry(&cache, &entry) && "FAIL: Cannot add entry to cache");

    assert(3 == get_cache_size(&cache) && "FAIL: Expected cache size 3");

    assert(0 == remove_cache_entry(&cache, entry.domain.name) && "FAIL: Cannot remove entry to cache");
    assert(0 == remove_cache_entry(&cache, entry.domain.name) && "FAIL: Cannot remove entry to cache");
    assert(0 == remove_cache_entry(&cache, entry.domain.name) && "FAIL: Cannot remove entry to cache");

    assert(0 == get_cache_size(&cache) && "FAIL: Expected cache size 0");

    free_cache_table(&cache);

    TEST_DEBUG(": PASS\n");
}

void test_hash_table_collision_handling(){
    TEST_DEBUG(":\n");
    DnsCacheTable_t cache;
    const char* domains[] = {"google.com", "yandex.com", "ya.ru",
                             "github.com", "linkedin.com", "youtube.com"};

    assert(0 == init_cache_table(&cache) && "FAIL: Fail to init cache table");

    size_t size = sizeof(domains) / sizeof(char*);
    for(size_t i = 0; i < size; i++){
        uint32_t hash = get_string_hash(domains[i], 10);
        BlacklistDomain_t temp_domain = {
            .name = domains[i],
            .redirect_ip = 0,
            .type = BLACKLIST_DOMAIN_TYPE_NOT_FOUND
        };
        entry.domain = temp_domain;

        printf("%s HASH: %u\n", domains[i], hash);
        assert(0 == add_to_hash_table(cache.hash_table, hash, &entry) && "Fail to add entry to hash table");
    }
    // assert(size == get_cache_size(&cache) && "Expected different hash table size");
    char* domain = "youtube.com";
    assert(0 == remove_from_hash_table(cache.hash_table, get_string_hash(domain, 10), domain) && "Fail to remove entry");

    free_cache_table(&cache);
    TEST_DEBUG(": PASS\n");
}

#ifdef CACHE_CLEANUP_INTERVAL
#undef CACHE_CLEANUP_INTERVAL
#define CACHE_CLEANUP_INTERVAL (2)
#endif
void test_validator(){
    TEST_DEBUG(":\n");

    pthread_t validator_th;
    DnsCacheTable_t cache;
    assert(0 == init_cache_table(&cache));

    BlacklistDomain_t temp_domain = {
        .name = "youtube.com",
        .redirect_ip = 0,
        .type = BLACKLIST_DOMAIN_TYPE_NOT_FOUND
    };
    entry.domain = temp_domain;
    entry.valid = 1;
    entry.timestamp = time(NULL);
    entry.ttl = 1;
    assert(0 == add_cache_entry(&cache, &entry));

    sleep(2);
    assert(0 == pthread_create(&validator_th, NULL, thread_cache_validator, (void*)&cache));
    sleep(2);

    char* domain_name = "youtube.com";
    DnsCacheEntry_t* cur_entry = get_cache_entry(&cache, domain_name);
    assert(cur_entry == NULL);

    entry.domain = temp_domain;
    entry.valid = 1;
    entry.timestamp = time(NULL);
    entry.ttl = 10;
    assert(0 == add_cache_entry(&cache, &entry));
    cur_entry = get_cache_entry(&cache, domain_name);
    assert(cur_entry != NULL);

    cache.active = false;
    pthread_join(validator_th, NULL);
    free_cache_table(&cache);

    TEST_DEBUG(": PASS\n");
}

int main(int argc, char* argv[]){
    test_free_cache();
    test_collision_cache();
    test_remove_entry_cache();

    test_hash_table_collision_handling();
    test_validator();
    return 0;
}