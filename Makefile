app := proxy-dns

all: clean build

build: main.c
	cc -g -O0 main.c -o $(app)

clean:
	rm -rf $(app)

