# Disposable lab image, not a production distribution.
FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY . .
ENV CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    (test -f Cargo.lock || cargo generate-lockfile) && \
    cargo build --locked -p satspathd --bin satspathd && \
    cargo build --locked -p satspath-core --example lab_client && \
    mkdir /out && cp target/debug/satspathd target/debug/examples/lab_client /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /state/authority /state/replica /state/public /state/alice /state/client \
    && chown -R 10001:10001 /state && chmod 700 /state/*
COPY --from=build /out/satspathd /out/lab_client /usr/local/bin/
USER 10001:10001
WORKDIR /state
CMD ["satspathd", "--help"]
