FROM public.repo.smartech.ir/library/rust:slim AS builder

WORKDIR /build

# Cache deps separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release --locked 2>/dev/null || true
RUN rm -rf src

COPY src ./src
COPY templates ./templates
COPY static ./static
RUN touch src/main.rs && cargo build --release --locked

# ── Final image ────────────────────────────────────────────────────────────────
FROM public.repo.smartech.ir/library/debian:bookworm-slim

RUN useradd --system --no-create-home --uid 10001 grafter

WORKDIR /app

COPY --from=builder /build/target/release/grafter ./grafter
COPY --from=builder /build/templates ./templates
COPY static ./static
RUN chown -R grafter:grafter /app

USER grafter

EXPOSE 3000

ENTRYPOINT ["./grafter"]
