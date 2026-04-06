FROM rust:1.84-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends bash && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/armory-verifier /usr/local/bin/armory-verifier

ENTRYPOINT ["armory-verifier"]
