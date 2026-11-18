ARG BASE_IMAGE=benchlab-adapter-base-ida:latest
ARG RUST_IMAGE=rust:1-bookworm
ARG IDA_SDK_TAG=v9.5.0-release

FROM ${RUST_IMAGE} AS rust-toolchain

FROM ${BASE_IMAGE} AS build
ARG IDA_SDK_TAG
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:${PATH}
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    clang libclang-dev cmake git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --quiet --depth 1 --branch "${IDA_SDK_TAG}" https://github.com/HexRaysSA/ida-sdk /opt/ida-sdk \
    && test -f /opt/ida-sdk/src/include/pro.h
COPY . /src
WORKDIR /src
ENV IDASDK_ROOT=/opt/ida-sdk/src \
    IDADIR=/opt/ida
RUN cargo build --release --bin capa-rs --features ida-backend,dotnet \
    && rm -rf /src/capa-rules/.github

FROM ${BASE_IMAGE}
COPY --from=build /src/target/release/capa-rs /usr/local/bin/capa-rs
COPY --from=build /src/capa-rules /opt/capa-rules
# capa's FLIRT signatures (Apache-2.0, FLAIR .sig), shipped but NOT applied by default:
# FLIRT is opt-in via `capa-rs --signatures /opt/capa-rs/sigs` or CAPA_SIGS_DIR (the
# adapter sets neither). IDA's plan_to_apply_idasgn only accepts a short file name, so
# the files are also placed in IDA's sig/pc directory.
COPY --from=build /src/sigs /opt/capa-rs/sigs
RUN mkdir -p /opt/ida/sig/pc && cp /opt/capa-rs/sigs/*.sig /opt/ida/sig/pc/
COPY --from=build /src/enhanced-dotnet-rules /opt/enhanced-dotnet-rules
ENV CAPA_RULES=/opt/capa-rules \
    IDADIR=/opt/ida \
    LD_LIBRARY_PATH=/opt/ida \
    TVHEADLESS=1 \
    IDAUSR=/root/.idapro
RUN capa-rs --version
COPY --from=bench adapter.py bench.toml /bench/
COPY --from=bench fixtures /bench/fixtures
LABEL benchlab.adapter="1" benchlab.role="adapter" benchlab.tool="capa-rs" benchlab.tool_version="runtime"
