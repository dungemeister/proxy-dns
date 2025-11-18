APP := proxy-dns
FLAGS := -Wall -Wextra -Wpedantic -g -O0 -lpthread -std=gnu99
DEBUG_FLAGS := ${FLAGS} -DDEBUG
BUILD_DIR := build

UNIT_TESTS_DIR := unit_tests
#Cache tests
CACHE_TESTS_DIR := cache_tests
CACHE_TEST_BUILD_PATH := ${BUILD_DIR}/${UNIT_TESTS_DIR}
CACHE_TEST_INC_DIRS := -I${UNIT_TESTS_DIR}/
CACHE_TESTS_FLAGS := -Wall -Wextra -g -O2 -lpthread -DDEBUG ${CACHE_TEST_INC_DIRS} -std=gnu99
#Server tests
SERVER_TESTS_DIR := server_tests
SERVER_TEST_BUILD_PATH := ${BUILD_DIR}/${UNIT_TESTS_DIR}
SERVER_INC_DIRS := -I${UNIT_TESTS_DIR}/
SERVER_TESTS_FLAGS := -Wall -Wextra -Wunused-function -g -O2 -lpthread -DDEBUG ${SERVER_INC_DIRS} 
#Queue tests
QUEUE_TESTS_DIR := queue_tests
QUEUE_TEST_BUILD_PATH := ${BUILD_DIR}/${UNIT_TESTS_DIR}
QUEUE_INC_DIRS := -I${UNIT_TESTS_DIR}/
QUEUE_TESTS_FLAGS := -Wall -Wextra -Wunused-function -g -O2 -lpthread -DDEBUG ${QUEUE_TESTS_FLAGS} 

SANITIZE_FLAG := -fsanitize=address

.PHONY: all
all: ${APP}

${APP}: ${BUILD_DIR}
	cc $(DEBUG_FLAGS) main.c -o ${BUILD_DIR}/$(APP)

${BUILD_DIR}:
	mkdir -p ${BUILD_DIR}

.PHONY: tests
tests: cache_test server_test queue_test

.PHONY:
cache_test: mkdir_cache_test build_cache_test
mkdir_cache_test:
	mkdir -p ${CACHE_TEST_BUILD_PATH}
build_cache_test:
	cc ${CACHE_TESTS_FLAGS} ${UNIT_TESTS_DIR}/test_cache.c -o ${CACHE_TEST_BUILD_PATH}/test_cache
clean_cache_test:
	rm -f ${BUILD_DIR}/${UNIT_TESTS_DIR}/test_cache

.PHONY:
server_test: mkdir_server_test build_server_test
mkdir_server_test:
	mkdir -p ${SERVER_TEST_BUILD_PATH}
build_server_test:
	cc ${SERVER_TESTS_FLAGS} ${UNIT_TESTS_DIR}/test_server.c -o ${SERVER_TEST_BUILD_PATH}/test_server
clean_server_test:
	rm -f ${BUILD_DIR}/${UNIT_TESTS_DIR}/test_server

.PHONY:
queue_test: mkdir_queue_test build_queue_test
mkdir_queue_test:
	mkdir -p ${QUEUE_TEST_BUILD_PATH}
build_queue_test:
	cc ${QUEUE_TESTS_FLAGS} ${UNIT_TESTS_DIR}/test_queue.c -o ${QUEUE_TEST_BUILD_PATH}/test_queue
clean_queue_test:
	rm -f ${BUILD_DIR}/${UNIT_TESTS_DIR}/test_queue

.PHONY: rebuild
rebuild: clean build

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}/$(APP)

