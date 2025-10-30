# Multi-stage build for rpc-replay
FROM --platform=linux/amd64 ubuntu:22.04 AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Rust for linux/amd64
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.87 \
    && . /usr/local/cargo/env \
    && rustup target add x86_64-unknown-linux-gnu

# Set the working directory
WORKDIR /app

# Copy the entire workspace
COPY . .

# Create Python virtual environment (force recreation)
RUN rm -rf sequencer_venv || true
RUN python3 -m venv sequencer_venv

# Verify venv was created correctly
RUN ls -la sequencer_venv/bin/

# Install Python dependencies
RUN sequencer_venv/bin/pip install --upgrade pip

# Fetch cargo dependencies first
RUN . /usr/local/cargo/env && cargo fetch || true

# Install requirements if found
RUN if find /usr/local/cargo/git/checkouts -name "requirements.txt" -path "*/scripts/*" 2>/dev/null | head -1; then \
        REQS_FILE=$(find /usr/local/cargo/git/checkouts -name "requirements.txt" -path "*/scripts/*" | head -1); \
        echo "Found requirements.txt at: $REQS_FILE"; \
        sequencer_venv/bin/pip install -r "$REQS_FILE"; \
    else \
        echo "No requirements.txt found, skipping pip install"; \
    fi

# Build the rpc-replay binary
RUN . sequencer_venv/bin/activate \
    && . /usr/local/cargo/env \
    && cargo build --release --bin rpc-replay

# Runtime stage
FROM --platform=linux/amd64 ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libgmp10 \
    python3 \
    python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user
RUN useradd -m -u 1000 appuser

# Create directories for logs and output
RUN mkdir -p /app/output /app/logs && chown -R appuser:appuser /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rpc-replay /usr/local/bin/rpc-replay

# Copy Python virtual environment
COPY --from=builder /app/sequencer_venv /app/sequencer_venv

# COPY the bash script
COPY --from=builder /app/crates/rpc-replay/rpc-replay-binary.sh /app/rpc-replay-binary.sh

# Set proper permissions
RUN chmod +x /usr/local/bin/rpc-replay
RUN chmod +x /app/rpc-replay-binary.sh

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Set default environment variables (can be overridden at runtime)
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV RUST_LOG_STYLE=always
ENV AWS_S3_BUCKET=""
ENV AWS_ACCESS_KEY_ID=""
ENV AWS_SECRET_ACCESS_KEY=""
ENV PATH=/app/sequencer_venv/bin:$PATH

# Expose volumes for output files and logs
VOLUME ["/app/output", "/app/logs"]

# Health check to ensure the application is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep rpc-replay || exit 1

# Default command - passes all arguments to the binary
ENTRYPOINT ["rpc-replay"]
CMD ["--help"]
