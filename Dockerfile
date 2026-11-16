# capa-rs container: standalone capability detection (goblin + dotscope default,
# plus optional IDA Pro 9.5 idalib target).
#
# Build context = this directory (the capa-rs source tree):
#   docker build -t capa-rs:latest capa-rs
#
# Mirror / proxy overrides (only when public registries are blocked):
#   docker build -t capa-rs:latest \
#     --build-arg RUST_IMAGE=<mirror>/library/rust:1-bookworm \
#     --build-arg RUNTIME_IMAGE=<mirror>/library/debian:bookworm-slim capa-rs
#
# IDA 9.5 backend target (--backend ida, idalib). Not the default: the base image
# must already contain IDA Pro 9.5 at /opt/ida plus its license under /root/.idapro
# (xmre-ida-base does). This file never copies the IDA install or the license.
# IDA_SDK_TAG must match the IDA version in IDA_BASE (v9.5.0-release for IDA 9.5).
#   docker build --target ida -t capa-rs:ida \
#     --build-arg IDA_BASE=<registry>/xmre-ida-base:f07199d9 capa-rs

ARG RUST_IMAGE=rust:1-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim
# Optional cargo features enabled in both targets ("dotnet" enables pure-Rust
# dotscope CIL analysis; pass --build-arg FEATURES= for native-only).
ARG FEATURES=dotnet
# ida target only: IDA Pro 9.5 base image (IDA at /opt/ida) and matching public
# HexRaysSA/ida-sdk tag. Placeholder fails fast with a clear name if --target ida
# is invoked without --build-arg IDA_BASE.
ARG IDA_BASE=ida-base-not-set-use-build-arg
ARG IDA_SDK_TAG=v9.5.0-release

FROM ${RUST_IMAGE} AS build
ARG FEATURES
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends clang cmake \
    && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src
RUN cargo build --release --bin capa-rs ${FEATURES:+--features ${FEATURES}} \
    && rm -rf /src/capa-rules/.github

# ---- ida target: docker build --target ida --build-arg IDA_BASE=<image> ----
# Rust toolchain taken from the same RUST_IMAGE the default build uses (the IDA base has none).
FROM ${RUST_IMAGE} AS rust-toolchain

FROM ${IDA_BASE} AS ida-build
ARG FEATURES
ARG IDA_SDK_TAG
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:${PATH}
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends clang libclang-dev cmake git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Public SDK headers and stubs only (no IDA binaries or license). Not copied into the final image.
RUN git clone --quiet --depth 1 --branch "${IDA_SDK_TAG}" https://github.com/HexRaysSA/ida-sdk /opt/ida-sdk \
    && test -f /opt/ida-sdk/src/include/pro.h
COPY . /src
WORKDIR /src
ENV IDASDK_ROOT=/opt/ida-sdk/src IDADIR=/opt/ida
RUN cargo build --release --bin capa-rs --features ida-backend${FEATURES:+,${FEATURES}} \
    && rm -rf /src/capa-rules/.github

FROM ${IDA_BASE} AS ida
COPY --from=ida-build /src/target/release/capa-rs /usr/local/bin/capa-rs
COPY --from=ida-build /src/capa-rules /opt/capa-rules
COPY --from=ida-build /src/enhanced-dotnet-rules /opt/enhanced-dotnet-rules
# libida.so / libidalib.so live in /opt/ida; the license stays in the base image's /root/.idapro.
ENV CAPA_RULES=/opt/capa-rules \
    IDADIR=/opt/ida \
    LD_LIBRARY_PATH=/opt/ida \
    TVHEADLESS=1
RUN capa-rs --version
ENTRYPOINT ["capa-rs"]

# ---- default target (keep this stage last: a plain `docker build` builds the last stage) ----
FROM ${RUNTIME_IMAGE}
COPY --from=build /src/target/release/capa-rs /usr/local/bin/capa-rs
COPY --from=build /src/capa-rules /opt/capa-rules
COPY --from=build /src/enhanced-dotnet-rules /opt/enhanced-dotnet-rules
ENV CAPA_RULES=/opt/capa-rules
RUN capa-rs --version
ENTRYPOINT ["capa-rs"]
