FROM rust:slim AS builder

WORKDIR /build

# Cache deps separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release --locked 2>/dev/null || true
RUN rm -rf src

COPY src ./src
COPY templates ./templates
RUN touch src/main.rs && cargo build --release --locked

# ── Final image ────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

COPY --from=builder /build/target/release/grafter ./grafter
COPY --from=builder /build/templates ./templates

EXPOSE 3000

ENTRYPOINT ["./grafter"]
