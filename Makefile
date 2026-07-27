.PHONY: build-dev build run-dev run bpftool clean clean-ebpf build-ebpf


BPFTOOL="bpftool"
CLANG ?= clang

bpftool:
	git clone --recurse-submodules https://github.com/libbpf/bpftool
	
	cd bpftool/src
	make
	sudo make install
	
	/usr/local/sbin/bpftool version
	sudo cp /usr/local/sbin/bpftool /usr/sbin/bpftool
	
	bpftool version
	git clone --recurse-submodules https://github.com/libbpf/bpftool
	
	cd bpftool/src
	make
	sudo make install
	
	/usr/local/sbin/bpftool version
	sudo cp /usr/local/sbin/bpftool /usr/sbin/bpftool
	
	bpftool version


build-dev:
	cargo build

build-ebpf:
	$(MAKE) -C ebpf

build:
	cargo build --release

run-dev:
	make build-dev
	./target/debug/rfw

run:
	make build
	./target/release/rfw

clean-ebpf:
	$(MAKE) -C ebpf clean

clean:
	rm -f ebpf/*.o
