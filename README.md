# Anchorpoint-IT Web Suite

A level-headed network management and diagnostics suite designed for real-time system monitoring and remote network testing.

## Recent Updates
- **Secure Authentication**: Transitioned to Bcrypt password hashing (cost factor 12) for all user accounts.
- **User Management**: Added a "Site Settings" dashboard allowing administrators to create and manage authorized users directly from the UI.
- **Persistent Storage**: Integrated SQLite for localized, high-performance data persistence on the VPS.
- **Rebranding**: Complete "Midnight" UI overhaul with glassmorphism components and optimized log viewing.

## Tech Stack
- **Backend**: Go (Golang) 1.24
- **Database**: SQLite3
- **Security**: x/crypto/bcrypt
- **Infrastructure**: Docker & Docker Compose

## Deployment
Run the automated deployment script:
```bash
make deploy