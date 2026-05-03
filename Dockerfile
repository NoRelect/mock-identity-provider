FROM rust:1.95 AS builder
WORKDIR /code
COPY Cargo.toml Cargo.lock /code/
COPY src /code/src
RUN cargo build --release
RUN BIN_PATH=$(find /code -name mock-identity-provider) && \
    cp ${BIN_PATH} /mock-identity-provider

FROM scratch
COPY --from=builder /mock-identity-provider /mock-identity-provider
COPY www /www
COPY config.json /config.json
USER 1000
ENTRYPOINT [ "/mock-identity-provider" ]
