# NIT Warangal - Academic Records Blockchain Network

> **A Production-Grade Hyperledger Fabric Network for Academic Record Management**

[![Hyperledger Fabric](https://img.shields.io/badge/Hyperledger%20Fabric-2.5-blue)](https://www.hyperledger.org/use/fabric)
[![Go](https://img.shields.io/badge/Go-1.21-00ADD8)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Network Components](#network-components)
- [Getting Started](#getting-started)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Contributing](#contributing)
- [License](#license)

---
## Video
https://drive.google.com/file/d/1CLfr22A4T6tLuH0S9R1lNe2uIhsbw4B5/view?usp=sharing
## Frontend 
https://github.com/princekumar828/Academic-Records-Blockchain---Frontend
## Backend
https://github.com/princekumar828/Academic-Records-Blockchain-Backend

## 🎯 Overview

This project implements a **permissioned blockchain network** using **Hyperledger Fabric 2.5** for managing academic records at NIT Warangal. It provides a secure, transparent, and tamper-proof system for storing student records, academic transcripts, certificates, and course information.

### Why Blockchain for Academic Records?

- **🔒 Immutability**: Academic records cannot be tampered with once recorded
- **🔍 Transparency**: Verifiable audit trail of all record modifications
- **🚀 Efficiency**: Instant verification of credentials without manual intervention
- **🔐 Privacy**: Sensitive data protected using Private Data Collections (PDC)
- **🤝 Trust**: Multi-organization consensus ensures data integrity
- **⚡ Automation**: Smart contracts automate business logic and validation

---

## 🏗️ Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NIT Warangal Blockchain Network                   │
│                     (academic-records-channel)                       │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │    Ordering Service       │
                    │   (Raft Consensus)        │
                    │  orderer.nitw.edu:7050    │
                    │   OrdererMSP              │
                    └─────────────┬─────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
┌─────────▼─────────┐   ┌────────▼────────┐   ┌─────────▼─────────┐
│  NITWarangal Org  │   │ Departments Org │   │   Verifiers Org   │
│  (NITWarangalMSP) │   │ (DepartmentsMSP)│   │  (VerifiersMSP)   │
├───────────────────┤   ├─────────────────┤   ├───────────────────┤
│ peer0:7051        │   │ peer0:9051      │   │ peer0:11051       │
│ CouchDB:5984      │   │ CouchDB:6984    │   │ CouchDB:8984      │
│ CA:7054           │   │ CA:8054         │   │ CA:9054           │
├───────────────────┤   ├─────────────────┤   ├───────────────────┤
│ Actors:           │   │ Actors:         │   │ Actors:           │
│ • Admin/Dean      │   │ • Dept Heads    │   │ • Employers       │
│ • Registrar       │   │ • Faculty       │   │ • Universities    │
│ • Students        │   │ • Staff         │   │ • Govt Agencies   │
└───────────────────┘   └─────────────────┘   └───────────────────┘
```

### Data Flow Architecture

```
┌──────────────┐
│   Frontend   │ (Angular 17 - Port 4200)
│   (Web App)  │
└──────┬───────┘
       │ HTTP/REST
       │
┌──────▼───────┐
│   Backend    │ (Node.js/Express - Port 3000)
│  REST API    │
└──────┬───────┘
       │ Fabric SDK
       │
┌──────▼────────────────────────────────────┐
│      Hyperledger Fabric Network           │
│  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Peer 0   │  │ Peer 1   │  │ Peer 2  │ │
│  │ NITWgal  │  │ Dept     │  │ Verif   │ │
│  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│       │             │             │       │
│  ┌────▼─────────────▼─────────────▼────┐ │
│  │         Chaincode (Smart Contract)   │ │
│  │        (Go - academic-records)       │ │
│  └────┬─────────────┬─────────────┬────┘ │
│       │             │             │       │
│  ┌────▼─────┐  ┌───▼──────┐  ┌───▼────┐ │
│  │ CouchDB  │  │ CouchDB  │  │CouchDB │ │
│  │ State DB │  │ State DB │  │StateDB │ │
│  └──────────┘  └──────────┘  └────────┘ │
└───────────────────────────────────────────┘
```

---

## ✨ Key Features

### 🎓 Academic Record Management
- **Student Profiles**: Complete student information with enrollment details
- **Academic Records**: Semester-wise grades, credits, and transcripts
- **Certificate Management**: Degree certificates, course completion certificates
- **Course Catalog**: Comprehensive course information across departments

### 🔐 Security & Privacy
- **Attribute-Based Access Control (ABAC)**: Role-based permissions (Admin, Faculty, Student, Verifier)
- **Private Data Collections (PDC)**: Sensitive data (Aadhaar, phone, personal email) stored privately
- **Identity Management**: Fabric CA for digital certificate issuance
- **TLS Communication**: All network communication encrypted

### 🏢 Multi-Organization Support
- **NITWarangal Organization**: Main academic institution
- **Departments Organization**: Individual department control
- **Verifiers Organization**: External credential verification

### 📊 Advanced Features
- **Multi-Department Architecture**: CSE, ECE, MECH, CIVIL departments
- **Workflow Management**: Record submission, approval, rejection workflows
- **Audit Trail**: Complete history of all transactions
- **Query Capabilities**: Rich queries using CouchDB indexes
- **Event Notifications**: Real-time blockchain event listeners

---

## 🧩 Network Components

### Organizations (3)

| Organization | MSP ID | Domain | Purpose | Actors |
|-------------|--------|--------|---------|--------|
| **NIT Warangal** | NITWarangalMSP | nitwarangal.nitw.edu | Main academic institution | Admin, Dean, Registrar, Students |
| **Departments** | DepartmentsMSP | departments.nitw.edu | Department-level operations | Department Heads, Faculty, Staff |
| **Verifiers** | VerifiersMSP | verifiers.nitw.edu | External verification | Employers, Universities, Agencies |

### Peers (3)

| Peer | Organization | Address | CouchDB | Role |
|------|--------------|---------|---------|------|
| **peer0.nitwarangal** | NITWarangal | localhost:7051 | localhost:5984 | Endorsing, Committing |
| **peer0.departments** | Departments | localhost:9051 | localhost:6984 | Endorsing, Committing |
| **peer0.verifiers** | Verifiers | localhost:11051 | localhost:8984 | Endorsing, Committing |

### Orderer (1)

| Component | Type | Address | Purpose |
|-----------|------|---------|---------|
| **orderer.nitw.edu** | Raft | localhost:7050 | Transaction ordering and block creation |

### Certificate Authorities (4)

| CA | Organization | Port | Purpose |
|----|--------------|------|---------|
| **ca_orderer** | Orderer | 7054 | Orderer identities |
| **ca_nitwarangal** | NITWarangal | 7054 | NITWarangal identities |
| **ca_departments** | Departments | 8054 | Departments identities |
| **ca_verifiers** | Verifiers | 9054 | Verifiers identities |

### Channel

| Name | Organizations | Purpose |
|------|---------------|---------|
| **academic-records-channel** | NITWarangalMSP, DepartmentsMSP, VerifiersMSP | Shared ledger for academic records |

### Chaincode (Smart Contract)

| Name | Version | Language | Endorsement Policy |
|------|---------|----------|-------------------|
| **academic-records** | 2.0 | Go (Golang) | OR('NITWarangalMSP.peer', 'DepartmentsMSP.peer', 'VerifiersMSP.peer') |

---

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed:

| Software | Version | Purpose | Installation |
|----------|---------|---------|--------------|
| **Docker** | 20.10+ | Container runtime | [Install Docker](https://docs.docker.com/get-docker/) |
| **Docker Compose** | 1.29+ | Multi-container orchestration | [Install Compose](https://docs.docker.com/compose/install/) |
| **Go** | 1.21+ | Chaincode development | [Install Go](https://golang.org/dl/) |
| **Node.js** | 18.x | Backend API | [Install Node.js](https://nodejs.org/) |
| **npm** | 8.x+ | Package manager | Comes with Node.js |
| **Git** | 2.x+ | Version control | [Install Git](https://git-scm.com/downloads) |

#### Verify Installation

```bash
# Check Docker
docker --version
docker-compose --version

# Check Go
go version

# Check Node.js & npm
node --version
npm --version

# Check Git
git --version
```

### System Requirements

- **OS**: Linux (Ubuntu 20.04+), macOS (10.15+), or Windows 10/11 with WSL2
- **RAM**: Minimum 8GB (16GB recommended)
- **Storage**: 10GB free space
- **CPU**: 4 cores (8 cores recommended)

---

## ⚡ Quick Start

### Step 1: Clone the Repository

```bash
git clone https://github.com/princekumar828/Academic_RecordsBlockchain.git
cd nit-warangal-network
```

### Step 2: Start the Complete Network

```bash
# Option 1: Start everything (Network + Backend + Frontend)
./start-all.sh

# Option 2: Start network only
./network.sh up
```

### Step 3: Verify Network is Running

```bash
# Check all containers
docker ps

# Expected output: 10+ containers running:
# - orderer.nitw.edu
# - peer0.nitwarangal.nitw.edu
# - peer0.departments.nitw.edu
# - peer0.verifiers.nitw.edu
# - ca_orderer, ca_nitwarangal, ca_departments, ca_verifiers
# - couchdb containers (3)
# - cli container
```

### Step 4: Access the Application

- **Frontend**: http://localhost:4200
- **Backend API**: http://localhost:3000
- **API Health**: http://localhost:3000/health

### Step 5: Login Credentials

| Role | Username | Password | Organization |
|------|----------|----------|--------------|
| Admin | admin | admin123 | NITWarangal |
| Faculty | faculty1 | faculty123 | Departments |
| Student | CS21B001 | student123 | NITWarangal |

---

## 📚 Documentation

For detailed information, refer to these documentation files:

| Document | Description |
|----------|-------------|
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Complete architecture, design patterns, and technical details |
| **[SETUP_GUIDE.md](SETUP_GUIDE.md)** | Step-by-step setup instructions for new users |
| **[Chaincode README](chaincode-go/academic-records/README.md)** | Smart contract functions and API reference |
| **[Backend README](backend/README.md)** | REST API documentation |
| **[Frontend README](frontend/README.md)** | Web application guide |

---

## 📁 Project Structure

```
nit-warangal-network/
├── chaincode-go/                    # Smart Contracts (Chaincode)
│   └── academic-records/            # Academic records chaincode
│       ├── chaincode.go            # Main chaincode logic
│       ├── go.mod                  # Go dependencies
│       └── vendor/                 # Vendored dependencies
│
├── configtx/                        # Channel configuration
│   └── configtx.yaml               # Channel and org definitions
│
├── crypto-config.yaml               # Cryptographic material config
│
├── docker/                          # Docker configuration
│   └── docker-compose-net.yaml     # Network services definition
│
├── scripts/                         # Automation scripts
│   ├── registerEnroll.sh           # Identity enrollment
│   └── utils.sh                    # Helper functions
│
├── collections_config.json          # Private Data Collections config
│
├── network.sh                       # Main network control script
├── start-all.sh                     # Complete startup script
├── quick-start.sh                   # Quick start (assumes network running)
├── generate-connection-profiles.sh  # Generate connection profiles
│
├── backend/                         # Node.js REST API (see backend/README.md)
├── frontend/                        # Angular Web App (see frontend/README.md)
│
├── organizations/                   # Generated: Crypto material
├── channel-artifacts/               # Generated: Channel configs
├── system-genesis-block/            # Generated: Genesis block
│
├── ARCHITECTURE.md                  # Architecture documentation
├── SETUP_GUIDE.md                   # Setup guide
└── README.md                        # This file
```

---

## 🔄 Network Lifecycle Commands

### Start Network

```bash
# Complete setup (clean + start + deploy + test)
./network.sh up
```

### Stop Network

```bash
# Stop all containers and cleanup
./network.sh clean
```

### View Logs

```bash
# View all container logs
docker-compose -f docker/docker-compose-net.yaml logs -f

# View specific container logs
docker logs -f peer0.nitwarangal.nitw.edu
docker logs -f orderer.nitw.edu
```

### Restart Services

```bash
# Restart specific service
docker restart peer0.nitwarangal.nitw.edu

# Restart all services
docker-compose -f docker/docker-compose-net.yaml restart
```

---

## 🧪 Testing the Network

### Test Chaincode Functions

```bash
# The network.sh up command automatically runs tests
# To run tests manually after network is up:

# 1. Create a student
docker exec cli peer chaincode invoke \
  -C academic-records-channel \
  -n academic-records \
  -c '{"function":"CreateStudent","Args":["CS21B001","John Doe","CSE","2021","[email protected]","GENERAL"]}'

# 2. Query student
docker exec cli peer chaincode query \
  -C academic-records-channel \
  -n academic-records \
  -c '{"Args":["GetStudent","CS21B001"]}'

# 3. Submit academic record
docker exec cli peer chaincode invoke \
  -C academic-records-channel \
  -n academic-records \
  -c '{"function":"SubmitAcademicRecord","Args":["CS21B001","2021","1","8.5","20","Pass"]}'
```

### Test REST API

```bash
# Health check
curl http://localhost:3000/health

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Get all students (requires auth token)
curl http://localhost:3000/api/students/all \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## 🎭 Network Actors & Roles

### 1. Administrator (NITWarangal Org)
- **Role**: System administrator
- **Permissions**: 
  - Create/update students
  - Approve/reject records
  - Manage departments
  - Issue certificates
- **Use Cases**: System setup, user management, policy enforcement

### 2. Faculty (Departments Org)
- **Role**: Course instructors
- **Permissions**:
  - Submit student grades
  - Create course records
  - View department students
- **Use Cases**: Grade submission, course management

### 3. Student (NITWarangal Org)
- **Role**: End users
- **Permissions**:
  - View own records
  - Request certificates
  - View transcripts
- **Use Cases**: Self-service record access

### 4. Verifier (Verifiers Org)
- **Role**: External entities
- **Permissions**:
  - Verify student credentials
  - Query public records
  - Cannot access private data
- **Use Cases**: Credential verification, background checks

---

## 🛠️ Troubleshooting

### Network Won't Start

```bash
# Clean everything and start fresh
./network.sh clean
docker system prune -a --volumes
./network.sh up
```

### Port Conflicts

```bash
# Check ports in use
lsof -i :7050,7051,3000,4200

# Kill processes
kill -9 <PID>
```

### Backend Connection Issues

```bash
# Verify connection profile exists
ls organizations/peerOrganizations/nitwarangal.nitw.edu/connection-nitwarangal.json

# Check backend logs
tail -f backend.log
```

### Chaincode Issues

```bash
# View chaincode container logs
docker logs $(docker ps -q --filter name=academic-records)

# Reinstall chaincode
./network.sh clean
./network.sh up
```

---

## 📊 Monitoring & Maintenance

### View Network Status

```bash
# All running containers
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Network resource usage
docker stats

# Disk space usage
docker system df
```

### Backup & Recovery

```bash
# Backup blockchain data
docker exec peer0.nitwarangal.nitw.edu tar czf /tmp/ledger-backup.tar.gz /var/hyperledger/production

# Copy backup to host
docker cp peer0.nitwarangal.nitw.edu:/tmp/ledger-backup.tar.gz ./backups/
```

---

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

## 👥 Team

- **Author**: Prince Kumar
- **Institution**: NIT Warangal
- **Course**: Academic Records Management System
- **Technology**: Hyperledger Fabric 2.5

---

## 🙏 Acknowledgments

- Hyperledger Fabric Community
- Linux Foundation
- NIT Warangal Computer Science Department

---

## 📞 Support

For issues, questions, or contributions:

- **GitHub Issues**: [Create an issue](https://github.com/princekumar828/Academic_RecordsBlockchain/issues)
- **Documentation**: See [ARCHITECTURE.md](ARCHITECTURE.md) and [SETUP_GUIDE.md](SETUP_GUIDE.md)
- **Email**: [email protected]

---

**Made with ❤️ using Hyperledger Fabric**
