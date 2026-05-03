FROM ghcr.io/rust-cross/rust-musl-cross:${TARGETARCH}-musl AS builder
COPY Cargo.toml Cargo.lock /home/rust
COPY src /home/rust/src
RUN cargo build --release
RUN BIN_PATH=$(find /home/rust/target -name mock-identity-provider) && \
    cp ${BIN_PATH} /mock-identity-provider && \
    musl-strip /mock-identity-provider

FROM scratch
COPY --from=builder /mock-identity-provider /mock-identity-provider
COPY www /www
COPY config.json /config.json
USER 1000
ENTRYPOINT [ "/mock-identity-provider" ]