CLANG ?= clang


BPF_CFLAGS = -O2 -g -target bpf \
	-I./include \
	-I/usr/include \
	-I/usr/include/x86_64-linux-gnu


all: main.o


main.o: main.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@


clean:
	rm -f *.o
