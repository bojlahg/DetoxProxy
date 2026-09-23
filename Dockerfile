# Build stage
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
COPY data ./data
RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home detox
WORKDIR /app
COPY --from=build /src/target/release/detox-proxy /app/detox-proxy
COPY config.yaml /app/config.yaml
COPY data /app/data
USER detox
EXPOSE 8080
ENTRYPOINT ["/app/detox-proxy", "--config", "/app/config.yaml"]