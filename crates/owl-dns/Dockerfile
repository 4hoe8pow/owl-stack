# ---- Build Stage ----
FROM rust:1.77 as builder
WORKDIR /app
COPY ../../Cargo.toml ../../Cargo.lock ./
COPY . ./crates/owl-dns
COPY ../common-utils ../common-utils
COPY ../nat64 ../nat64
COPY ../owl-core ../owl-core
RUN cargo build --release --bin owl-dns

# ---- Runtime Stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/owl-dns /usr/local/bin/owl-dns
ENTRYPOINT ["/usr/local/bin/owl-dns"]
