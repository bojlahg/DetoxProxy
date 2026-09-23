# Build stage
FROM rust:1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
COPY data ./data
RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
LABEL maintainer="DetoxProxy team" org.opencontainers.image.title="detox-proxy" org.opencontainers.image.description="PII masking module"
RUN useradd --system --uid 10001 --no-create-home detox
WORKDIR /app
COPY --from=build /src/target/release/detox-proxy /app/detox-proxy
COPY config.yaml /app/config.yaml
COPY data /app/data
USER detox
EXPOSE 8080
ENTRYPOINT ["/app/detox-proxy", "--config", "/app/config.yaml"]