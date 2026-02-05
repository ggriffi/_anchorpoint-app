FROM golang:1.24-bookworm AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o anchorpoint-app ./cmd/web

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
    mtr-tiny iputils-ping traceroute ca-certificates \
    curl gnupg iperf3 speedtest-cli libcap2-bin \
    dnsutils whois netbase procps psmisc \
    && rm -rf /var/lib/apt/lists/*

# Add Docker CLI logic
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && apt-get install -y docker-ce-cli && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/anchorpoint-app .
COPY --from=builder /app/web ./web
RUN touch info.log && chmod 666 info.log
RUN setcap cap_net_raw,cap_net_admin,cap_kill+ep ./anchorpoint-app && \
    setcap cap_net_raw+ep $(which mtr) && \
    setcap cap_net_raw+ep $(which ping)

EXPOSE 4000
CMD ["./anchorpoint-app"]