# ActPlane build. The Rust collector embeds the compiled bpf/process binary
# (include_bytes!), so eBPF must build before the Rust binary.
build: build-bpf build-rust

build-bpf:
	make -C bpf

build-rust: build-bpf
	cd collector && cargo build --release

clean:
	make -C bpf clean
	cd collector && cargo clean

install:
	sudo apt update
	sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
	# Install Rust if not present
	@command -v cargo >/dev/null 2>&1 || { \
		echo "Installing Rust..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		source ~/.cargo/env; \
	}

test:
	make -C bpf test
	cd collector && cargo test

.PHONY: build build-bpf build-rust clean install test
