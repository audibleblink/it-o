FROM golang:1.22-bullseye

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    automake \
    libtool \
    gcc \
    pkg-config \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build YARA dependencies first, then the static binary
RUN make deps && make clean && make yara && make ito

# Final stage - just the binary
FROM scratch
COPY --from=0 /app/ito /ito
ENTRYPOINT ["/ito"]