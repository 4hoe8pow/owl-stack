# ---- Build Stage ----
FROM rust:1.77 as builder
WORKDIR /app
COPY ../../Cargo.toml ../../Cargo.lock ./
COPY . ./crates/owl-core
COPY ../common-utils ../common-utils
COPY ../nat64 ../nat64
COPY ../owl-dns ../owl-dns
RUN cargo build --release --bin owl-core

# ---- Runtime Stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/owl-core /usr/local/bin/owl-core
ENTRYPOINT ["/usr/local/bin/owl-core"]
