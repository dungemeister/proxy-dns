APP := proxy-dns
FLAGS := -Wall -Wextra -Wpedantic -g -O0

all: clean build

build: main.c
	cc $(FLAGS) main.c -o $(APP)

clean:
	rm -rf $(APP)

