# Anchorpoint-IT Network Diagnostic Dashboard

A professional, level-headed network utility belt designed for **Anchorpoint-IT.com**. This Go-based web application provides a "Single Pane of Glass" for monitoring host infrastructure and performing real-time network path analysis.

## 🚀 Features

* **Real-Time Network Tools**: Integrated support for ICMP Ping, Traceroute, and MTR reporting directly from the host environment.
* **Privacy-First Redaction**: Automatically sanitizes reports by replacing internal infrastructure IPs (like your VLAN gateway and modem) with generic labels to keep your network topology private.
* **Infrastructure Monitoring**: A dedicated Docker status card that lists active containers on the host for quick service verification.
* **Smart Client Detection**: Automatically identifies the visitor's public IP address to provide intelligent default targets for diagnostic tests.
* **System Health Guts**: Real-time display of application memory usage and external gateway connectivity status.



## 🛠️ Technical Stack

* **Backend**: Go (Golang)
* **Frontend**: Go Templates, HTML5, and CSS3
* **Containerization**: Docker with Multi-Stage builds for a lean production image
* **Networking**: Host-mode networking for accurate Layer 3 hop reporting

## 📦 Deployment

This application is containerized for easy deployment on Debian-based hosts.

### Prerequisites
* Docker and Docker Compose installed.
* Access to the Docker socket (`/var/run/docker.sock`) for container monitoring.

### Installation
1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/ggriffi/anchorpoint-app.git](https://github.com/your-username/anchorpoint-app.git)
    cd anchorpoint-app
    ```
2.  **Build and Run**:
    ```bash
    docker compose up -d --build
    ```



## 🔒 Security & Privacy

This tool is built with a "Security First" mindset. It uses `setcap` to allow the application to perform raw network operations (Ping/MTR) without requiring full root privileges. Furthermore, all output is passed through a sanitization layer to ensure internal business IP addresses are never exposed to the public web.

## 👤 Author
**Geoff Griffith** *Main Business: [Anchorpoint-IT.com](https://anchorpoint-it.com)*

---