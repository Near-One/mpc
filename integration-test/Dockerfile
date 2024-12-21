FROM lukemathwalker/cargo-chef:latest AS chef
RUN apt-get update -y && apt-get install -y --no-install-recommends clang  # needed for rocksdb
WORKDIR /app

FROM chef AS planner

COPY node node
COPY utils utils
COPY Cargo.lock Cargo.lock
COPY Cargo.toml Cargo.toml
COPY .git .git
COPY .gitmodules .gitmodules

RUN git submodule update --init --recursive
RUN cargo chef prepare --recipe-path /app/recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
COPY .git .git
COPY .gitmodules .gitmodules

RUN git submodule update --init --recursive
RUN cargo chef cook --release --recipe-path recipe.json

COPY node node
COPY utils utils
COPY Cargo.lock Cargo.lock
COPY Cargo.toml Cargo.toml

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends openssl ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/mpc-node mpc-node
CMD [ "/bin/sh", "-c", "[ ! -f /app/data/key ] && ./mpc-node generate-key; ./mpc-node start" ]
