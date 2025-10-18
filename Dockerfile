# =========================
# 1️⃣  Build Stage
# =========================
FROM rust:1.81-slim AS builder

# Install required tools (if you need OpenSSL, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev build-essential && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside container
WORKDIR /app

# Cache dependencies:
# Copy Cargo.toml and Cargo.lock separately to leverage Docker caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy project to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY . .

# Build your actual app
RUN cargo build --bin cli --release

# =========================
# 2️⃣  Runtime Stage
# =========================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies (optional, only if your binary needs them)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled binary from builder
COPY --from=builder /app/target/release/cli /usr/local/bin/app

# Run as non-root user for security
RUN useradd -m node
USER node

# Start the app
ENTRYPOINT ["/usr/local/bin/app"]

