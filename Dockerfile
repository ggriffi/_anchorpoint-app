# Stage 1: Build the binary
FROM golang:1.22-bookworm AS builder
WORKDIR /app
COPY go.mod ./
# If you have a go.sum, uncomment the next line
# COPY go.sum ./
RUN go mod download
COPY . .
RUN go build -o anchorpoint-app ./cmd/web

# Stage 2: Final image
FROM debian:bookworm-slim
WORKDIR /app

# Install dependencies for adding a repo
RUN apt-get update && apt-get install -y \
    mtr-tiny \
    iputils-ping \
    traceroute \
    ca-certificates \
    curl \
    gnupg \
    iperf3 \
    speedtest-cli \
    && rm -rf /var/lib/apt/lists/*

# Add Docker's official GPG key and repo to get the latest CLI
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install only the docker-ce-cli (to keep the image small)
RUN apt-get update && apt-get install -y docker-ce-cli && rm -rf /var/lib/apt/lists/*

# Copy the rest of your app bits
COPY --from=builder /app/anchorpoint-app .
COPY --from=builder /app/web ./web
RUN touch info.log && chmod 666 info.log

# Set capabilities (Permissions logic)
RUN setcap cap_net_raw+ep $(which mtr) && \
    setcap cap_net_raw+ep $(which ping)

EXPOSE 4000
CMD ["./anchorpoint-app"]