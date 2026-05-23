FROM ubuntu:24.04

WORKDIR /app

# Install runtime dependencies for eBPF binaries
RUN apt-get update \
    && apt-get install -y --no-install-recommends libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY collector/target/release/actplane /app/actplane

RUN chmod +x /app/actplane

ENTRYPOINT ["/app/actplane"]
