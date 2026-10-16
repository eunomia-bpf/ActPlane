# ActPlane build. The Rust CLI links the eBPF engine crate, so eBPF must build
# before the Rust binary.
build: build-bpf build-rust

build-bpf:
	make -C bpf

build-rust: build-bpf
	cargo build --release -p actplane

clean:
	make -C bpf clean
	cargo clean -p actplane-ifc-compiler
	cargo clean -p actplane-runtime
	cargo clean -p actplane

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
	cargo test --workspace

# Lint the committed empirical-study evidence. Separate from `test` because it
# validates committed data rather than building or exercising code.
check-evidence:
	bash script/check_evidence_tsv.sh

# Lint committed doc references. Like `check-evidence`, this validates committed
# text rather than building or exercising code, so it stays out of `test`.
check-docs:
	python3 script/check_doc_refs.py


.PHONY: build build-bpf build-rust clean install test check-evidence check-docs
