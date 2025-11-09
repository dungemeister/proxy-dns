APP := proxy-dns
FLAGS := -Wall -Wextra -Wpedantic -g -O0
BUILD_DIR := build

.PHONY: all
all: ${APP}

${APP}: ${BUILD_DIR} main.c
	cc $(FLAGS) main.c -o ${BUILD_DIR}/$(APP)

${BUILD_DIR}:
	mkdir -p ${BUILD_DIR}

.PHONY: rebuild
rebuild: clean build

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}/$(APP)

