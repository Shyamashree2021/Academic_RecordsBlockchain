# NIT Warangal Academic Records - Complete Setup Guide

> **Step-by-Step Installation and Configuration for New Users**

---

## 📋 Table of Contents

- [Prerequisites Installation](#prerequisites-installation)
- [System Preparation](#system-preparation)
- [Network Setup](#network-setup)
- [Chaincode Deployment](#chaincode-deployment)
- [Backend Configuration](#backend-configuration)
- [Frontend Setup](#frontend-setup)
- [Testing & Verification](#testing--verification)
- [Common Issues](#common-issues)
- [Advanced Configuration](#advanced-configuration)

---

## 🔧 Prerequisites Installation

### Step 1: Install Docker

#### For Ubuntu/Debian Linux

```bash
# Update package index
sudo apt-get update

# Install dependencies
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Set up stable repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Add user to docker group (no sudo required)
sudo usermod -aG docker $USER

# Log out and back in for group change to take effect

# Verify installation
docker --version
docker run hello-world
```

#### For macOS

```bash
# Using Homebrew
brew install --cask docker

# Or download Docker Desktop from:
# https://www.docker.com/products/docker-desktop

# Start Docker Desktop application

# Verify installation
docker --version
```

#### For Windows 10/11

1. **Enable WSL2** (Windows Subsystem for Linux):
```powershell
# Run PowerShell as Administrator
wsl --install
wsl --set-default-version 2
```

2. **Install Docker Desktop**:
   - Download from: https://www.docker.com/products/docker-desktop
   - Run installer
   - Enable WSL2 integration
   - Restart computer

3. **Verify**:
```bash
docker --version
```

### Step 2: Install Docker Compose

#### For Linux

```bash
# Download Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# Make executable
sudo chmod +x /usr/local/bin/docker-compose

# Verify
docker-compose --version
```

#### For macOS/Windows

Docker Compose is included with Docker Desktop. Verify:

```bash
docker-compose --version
```

### Step 3: Install Go (Golang)

#### For Linux

```bash
# Download Go 1.21
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

# Remove old installation (if exists)
sudo rm -rf /usr/local/go

# Extract to /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Add to PATH (add to ~/.bashrc or ~/.zshrc)
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

# Reload shell configuration
source ~/.bashrc

# Verify
go version
```

#### For macOS

```bash
# Using Homebrew
brew install go@1.21

# Or download from: https://go.dev/dl/

# Verify
go version
```

#### For Windows

1. Download installer from: https://go.dev/dl/
2. Run the MSI installer
3. Verify in PowerShell:
```powershell
go version
```

### Step 4: Install Node.js and npm

#### For Linux (Ubuntu/Debian)

```bash
# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify
node --version
npm --version
```

#### For macOS

```bash
# Using Homebrew
brew install node@18

# Or use nvm (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.zshrc
nvm install 18
nvm use 18

# Verify
node --version
npm --version
```

#### For Windows

1. Download installer from: https://nodejs.org/ (LTS version)
2. Run installer
3. Verify in PowerShell:
```powershell
node --version
npm --version
```

### Step 5: Install Git

#### For Linux

```bash
sudo apt-get update
sudo apt-get install -y git

# Verify
git --version
```

#### For macOS

```bash
# Git comes with Xcode Command Line Tools
xcode-select --install

# Or use Homebrew
brew install git

# Verify
git --version
```

#### For Windows

1. Download from: https://git-scm.com/download/win
2. Run installer (use default settings)
3. Verify in PowerShell:
```powershell
git --version
```

### Step 6: Install Additional Tools (Optional but Recommended)

```bash
# jq (JSON processor)
sudo apt-get install -y jq  # Linux
brew install jq             # macOS

# curl (if not installed)
sudo apt-get install -y curl  # Linux

# make (build automation)
sudo apt-get install -y build-essential  # Linux
```

---

## 🖥️ System Preparation

### Step 1: Configure System Resources

#### For Docker Desktop (macOS/Windows)

1. Open Docker Desktop
2. Go to Settings → Resources
3. Configure:
   - **CPUs**: 4 or more
   - **Memory**: 8 GB or more
   - **Swap**: 2 GB
   - **Disk**: 50 GB or more
4. Click "Apply & Restart"

#### For Linux

```bash
# Check available resources
free -h
df -h
nproc

# Ensure at least:
# - 8 GB RAM
# - 10 GB free disk space
# - 4 CPU cores
```

### Step 2: Configure Docker

```bash
# Enable Docker to start on boot
sudo systemctl enable docker

# Start Docker service
sudo systemctl start docker

# Verify Docker is running
sudo systemctl status docker
```

### Step 3: Set Up Network Ports

Ensure the following ports are available:

| Port | Service | Purpose |
|------|---------|---------|
| 7050 | Orderer | Transaction ordering |
| 7051 | Peer0 (NITW) | Endorsement |
| 7053 | Orderer Admin | Channel management |
| 7054 | CA Orderer | Certificate Authority |
| 7054 | CA NITWarangal | Certificate Authority |
| 8054 | CA Departments | Certificate Authority |
| 9051 | Peer0 (Dept) | Endorsement |
| 9054 | CA Verifiers | Certificate Authority |
| 11051 | Peer0 (Verif) | Endorsement |
| 5984 | CouchDB0 | State database |
| 6984 | CouchDB1 | State database |
| 8984 | CouchDB2 | State database |
| 3000 | Backend API | REST API |
| 4200 | Frontend | Web application |

**Check for port conflicts**:

```bash
# Linux/macOS
lsof -i :7050,7051,3000,4200

# Windows
netstat -ano | findstr "7050 7051 3000 4200"
```

**Kill conflicting processes if needed**:

```bash
# Linux/macOS
kill -9 <PID>

# Windows (run as Administrator)
taskkill /PID <PID> /F
```

---

## 🌐 Network Setup

### Step 1: Clone the Repository

```bash
# Navigate to your workspace
cd ~/workspace  # or any directory you prefer

# Clone the repository
git clone https://github.com/princekumar828/Academic_RecordsBlockchain.git

# Navigate to network directory
cd Academic_RecordsBlockchain/nit-warangal-network

# Verify files
ls -la
```

**Expected files**:
```
network.sh
start-all.sh
quick-start.sh
crypto-config.yaml
collections_config.json
docker/
scripts/
configtx/
chaincode-go/
backend/
frontend/
```

### Step 2: Make Scripts Executable

```bash
# Make all scripts executable
chmod +x network.sh
chmod +x start-all.sh
chmod +x quick-start.sh
chmod +x generate-connection-profiles.sh
chmod +x scripts/*.sh
```

### Step 3: Start the Complete Network

```bash
# Clean any previous setup
./network.sh clean

# Start the network (this will take 5-10 minutes)
./network.sh up
```

**What happens during `./network.sh up`**:

1. ✅ **Cleanup**: Remove old containers, volumes, and artifacts
2. ✅ **Start CAs**: Launch 4 Certificate Authority containers
3. ✅ **Generate Identities**: Create certificates for all organizations
4. ✅ **Start Network**: Launch orderer and 3 peer containers
5. ✅ **Create Channel**: Create `academic-records-channel`
6. ✅ **Join Peers**: All 3 peers join the channel
7. ✅ **Package Chaincode**: Create chaincode package
8. ✅ **Install Chaincode**: Install on all 3 peers
9. ✅ **Approve Chaincode**: All 3 orgs approve
10. ✅ **Commit Chaincode**: Commit definition to channel
11. ✅ **Test Chaincode**: Run sample transactions

### Step 4: Verify Network is Running

```bash
# Check running containers
docker ps

# Expected output: 10+ containers
# - orderer.nitw.edu
# - peer0.nitwarangal.nitw.edu
# - peer0.departments.nitw.edu
# - peer0.verifiers.nitw.edu
# - ca_orderer
# - ca_nitwarangal
# - ca_departments
# - ca_verifiers
# - couchdb0, couchdb1, couchdb2
# - cli

# Check container logs
docker logs peer0.nitwarangal.nitw.edu
```

**Success indicators**:
- All containers show status "Up"
- No error messages in logs
- Test transactions completed successfully

---

## 📦 Chaincode Deployment

### Understanding the Chaincode

The chaincode is automatically deployed by `./network.sh up`, but here's what happens:

#### Step 1: Package Chaincode

```bash
# Manually package (if needed)
docker exec cli peer lifecycle chaincode package academic-records.tar.gz \
  --path /opt/gopath/src/github.com/hyperledger/fabric/peer/chaincode-go/academic-records \
  --lang golang \
  --label academic_records_2.0
```

#### Step 2: Install on Each Peer

```bash
# Install on NITW peer
docker exec -e CORE_PEER_ADDRESS=peer0.nitwarangal.nitw.edu:7051 \
  -e CORE_PEER_LOCALMSPID=NITWarangalMSP \
  cli peer lifecycle chaincode install academic-records.tar.gz

# Install on Departments peer
docker exec -e CORE_PEER_ADDRESS=peer0.departments.nitw.edu:9051 \
  -e CORE_PEER_LOCALMSPID=DepartmentsMSP \
  cli peer lifecycle chaincode install academic-records.tar.gz

# Install on Verifiers peer
docker exec -e CORE_PEER_ADDRESS=peer0.verifiers.nitw.edu:11051 \
  -e CORE_PEER_LOCALMSPID=VerifiersMSP \
  cli peer lifecycle chaincode install academic-records.tar.gz
```

#### Step 3: Query Package ID

```bash
docker exec cli peer lifecycle chaincode queryinstalled
```

#### Step 4: Approve for Each Organization

```bash
# Set package ID (get from queryinstalled)
PACKAGE_ID="academic_records_2.0:xxxxx..."

# Approve for NITWarangal
docker exec -e CORE_PEER_LOCALMSPID=NITWarangalMSP \
  cli peer lifecycle chaincode approveformyorg \
  --channelID academic-records-channel \
  --name academic-records \
  --version 2.0 \
  --package-id $PACKAGE_ID \
  --sequence 1

# Repeat for Departments and Verifiers
```

#### Step 5: Commit Chaincode

```bash
docker exec cli peer lifecycle chaincode commit \
  -o orderer.nitw.edu:7050 \
  --channelID academic-records-channel \
  --name academic-records \
  --version 2.0 \
  --sequence 1 \
  --peerAddresses peer0.nitwarangal.nitw.edu:7051 \
  --peerAddresses peer0.departments.nitw.edu:9051 \
  --peerAddresses peer0.verifiers.nitw.edu:11051
```

#### Step 6: Verify Deployment

```bash
# Check committed chaincode
docker exec cli peer lifecycle chaincode querycommitted \
  --channelID academic-records-channel

# Test invoke
docker exec cli peer chaincode invoke \
  -C academic-records-channel \
  -n academic-records \
  -c '{"function":"CreateDepartment","Args":["CSE","Computer Science","Prof. Kumar","[email protected]"]}'

# Test query
docker exec cli peer chaincode query \
  -C academic-records-channel \
  -n academic-records \
  -c '{"Args":["GetDepartment","CSE"]}'
```

---

## 🔧 Backend Configuration

### Step 1: Navigate to Backend Directory

```bash
cd backend
```

### Step 2: Install Dependencies

```bash
# Install Node.js packages
npm install

# Expected packages:
# - express (web framework)
# - fabric-network (Hyperledger Fabric SDK)
# - fabric-ca-client (CA SDK)
# - dotenv (environment variables)
# - cors (CORS middleware)
# - winston (logging)
# - express-rate-limit (rate limiting)
```

### Step 3: Configure Environment Variables

```bash
# Copy example environment file
cp .env.example .env

# Edit configuration (already set correctly for localhost)
nano .env  # or use any text editor
```

**Key Configuration** (`.env` file):

```bash
# Server Configuration
PORT=3000
HOST=0.0.0.0
NODE_ENV=development
API_PREFIX=/api

# Hyperledger Fabric Configuration
CHANNEL_NAME=academic-records-channel
CHAINCODE_NAME=academic-records
MSP_ID=NITWarangalMSP

# Connection Profile Path (relative to backend root)
CONNECTION_PROFILE_PATH=../organizations/peerOrganizations/nitwarangal.nitw.edu/connection-nitwarangal.json

# Wallet Path
WALLET_PATH=./wallet

# Admin Credentials
ADMIN_USER_ID=admin
ADMIN_PASSWORD=adminpw

# CA Configuration
CA_URL=https://localhost:7054
CA_NAME=ca-nitwarangal

# Logging
LOG_LEVEL=info
LOG_TO_FILE=true
LOG_FILE_PATH=./logs/backend.log

# Security (set strong values for production)
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=24h
CORS_ORIGIN=http://localhost:4200
```

### Step 4: Import Admin Identity

The admin identity needs to be enrolled and imported into the wallet:

```bash
# Import admin identity
node src/importAdmin.js
```

**Expected output**:
```
Successfully enrolled admin user and imported into wallet
```

**Verify wallet**:
```bash
ls -la wallet/
# Should show: admin.id
```

### Step 5: Start Backend Server

#### Development Mode (with auto-restart)

```bash
npm run dev
```

#### Production Mode

```bash
npm start
```

**Expected output**:
```
=== Application Configuration Summary ===
Environment: development
Server: 0.0.0.0:3000
API Prefix: /api
Channel: academic-records-channel
Chaincode: academic-records
MSP ID: NITWarangalMSP
=========================================

🚀 Academic Records Backend Server running on 0.0.0.0:3000
📡 Environment: development
🔗 API Base URL: http://localhost:3000/api
```

### Step 6: Test Backend API

```bash
# Health check
curl http://localhost:3000/health

# Expected response:
# {
#   "status": "OK",
#   "timestamp": "2025-11-17T...",
#   "environment": "development"
# }

# Login (get JWT token)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Expected response:
# {
#   "success": true,
#   "token": "eyJhbGc...",
#   "user": {
#     "username": "admin",
#     "role": "admin",
#     ...
#   }
# }
```

---

## 🎨 Frontend Setup

### Step 1: Navigate to Frontend Directory

```bash
cd ../frontend  # from backend directory
# OR
cd frontend  # from project root
```

### Step 2: Install Dependencies

```bash
# Install Angular dependencies
npm install

# This will install:
# - @angular/* packages
# - @angular/material
# - RxJS
# - TypeScript
# - And other dependencies
```

### Step 3: Configure API Endpoint

The API endpoint is already configured in `src/app/app.config.ts`:

```typescript
export const APP_CONFIG = {
  apiUrl: 'http://localhost:3000/api',
  appName: 'Academic Records Blockchain',
  version: '1.0.0'
};
```

### Step 4: Start Frontend Application

```bash
# Development server
npm start

# Or explicitly
ng serve
```

**Expected output**:
```
✔ Browser application bundle generation complete.
Initial Chunk Files   | Names         |  Raw Size
main.js              | main          |   2.5 MB  |
polyfills.js         | polyfills     | 333.0 kB  |
styles.css           | styles        | 276.4 kB  |

Build at: 2025-11-17T...
** Angular Live Development Server is listening on localhost:4200 **
✔ Compiled successfully.
```

### Step 5: Access the Application

1. Open browser: http://localhost:4200
2. You should see the login page
3. Use credentials:
   - **Username**: `admin`
   - **Password**: `admin123`

---

## ✅ Testing & Verification

### Test 1: Create a Student

1. Login as admin
2. Navigate to "Students" → "Create Student"
3. Fill in details:
   - **Student ID**: CS21B001
   - **Name**: John Doe
   - **Department**: CSE
   - **Batch**: 2021
   - **Email**: [email protected]
   - **Category**: GENERAL
4. Click "Create Student"
5. Verify success message

### Test 2: Submit Academic Record

1. Navigate to "Academic Records" → "Submit Record"
2. Fill in:
   - **Student ID**: CS21B001
   - **Year**: 2021
   - **Semester**: 1
   - **SGPA**: 8.5
   - **Credits**: 20
   - **Status**: Pass
3. Click "Submit"
4. Record should appear in "Pending Records"

### Test 3: Approve Record

1. As admin, navigate to "Pending Records"
2. Find the submitted record
3. Click "Approve"
4. Verify status changes to "Approved"

### Test 4: Issue Certificate

1. Navigate to "Certificates" → "Issue Certificate"
2. Select student: CS21B001
3. Select type: "Degree Certificate"
4. Click "Issue"
5. Download and verify certificate

### Test 5: Verify from Blockchain

```bash
# Query student from chaincode directly
docker exec cli peer chaincode query \
  -C academic-records-channel \
  -n academic-records \
  -c '{"Args":["GetStudent","CS21B001"]}'

# Should return student JSON
```

---

## 🔧 Common Issues

### Issue 1: Port Already in Use

**Error**: `Port 7050 is already in use`

**Solution**:
```bash
# Find process using port
lsof -i :7050

# Kill process
kill -9 <PID>

# Or kill all Docker containers
docker rm -f $(docker ps -aq)

# Restart network
./network.sh clean
./network.sh up
```

### Issue 2: Docker Permission Denied

**Error**: `permission denied while trying to connect to Docker daemon`

**Solution**:
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and log back in

# Or run with sudo (not recommended)
sudo ./network.sh up
```

### Issue 3: Connection Profile Not Found

**Error**: `Connection profile not found at ...`

**Solution**:
```bash
# Regenerate connection profiles
./generate-connection-profiles.sh

# Verify file exists
ls organizations/peerOrganizations/nitwarangal.nitw.edu/connection-nitwarangal.json

# Update .env file with correct path
cd backend
nano .env  # Fix CONNECTION_PROFILE_PATH
```

### Issue 4: Admin Identity Not Found

**Error**: `Identity admin not found in wallet`

**Solution**:
```bash
cd backend

# Remove old wallet
rm -rf wallet

# Re-import admin
node src/importAdmin.js

# Verify
ls wallet/
```

### Issue 5: Chaincode Installation Fails

**Error**: `Error: chaincode install failed`

**Solution**:
```bash
# Clean and restart
./network.sh clean

# Ensure Go dependencies are vendored
cd chaincode-go/academic-records
GO111MODULE=on go mod vendor

# Restart network
cd ../..
./network.sh up
```

### Issue 6: Frontend Build Fails

**Error**: `Module not found` or compilation errors

**Solution**:
```bash
cd frontend

# Clear cache
rm -rf node_modules package-lock.json

# Reinstall
npm install

# Clear Angular cache
rm -rf .angular

# Rebuild
npm start
```

### Issue 7: Backend Cannot Connect to Fabric

**Error**: `Failed to connect to gateway`

**Solution**:
```bash
# Check network is running
docker ps | grep peer0.nitwarangal

# Check connection profile
cat organizations/peerOrganizations/nitwarangal.nitw.edu/connection-nitwarangal.json

# Verify wallet
ls backend/wallet/

# Check backend logs
tail -f backend.log

# Restart backend
cd backend
npm run dev
```

---

## 🔐 Advanced Configuration

### Enable HTTPS for Backend

1. Generate SSL certificates:
```bash
cd backend
mkdir certs

openssl req -newkey rsa:2048 -nodes -keyout certs/key.pem \
  -x509 -days 365 -out certs/cert.pem
```

2. Update `server.js`:
```javascript
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('./certs/key.pem'),
  cert: fs.readFileSync('./certs/cert.pem')
};

https.createServer(options, app).listen(3443, () => {
  console.log('HTTPS Server running on port 3443');
});
```

### Configure Multiple Orderers (Production)

Edit `docker/docker-compose-net.yaml`:

```yaml
services:
  orderer1.nitw.edu:
    # ... configuration

  orderer2.nitw.edu:
    image: hyperledger/fabric-orderer:2.5
    # ... similar configuration with different ports

  orderer3.nitw.edu:
    image: hyperledger/fabric-orderer:2.5
    # ... similar configuration with different ports
```

Update `configtx/configtx.yaml`:

```yaml
Orderer:
  Addresses:
    - orderer1.nitw.edu:7050
    - orderer2.nitw.edu:8050
    - orderer3.nitw.edu:9050
```

### Add More Peers per Organization

Edit `docker-compose-net.yaml`:

```yaml
  peer1.nitwarangal.nitw.edu:
    image: hyperledger/fabric-peer:2.5
    environment:
      - CORE_PEER_ID=peer1.nitwarangal.nitw.edu
      - CORE_PEER_ADDRESS=peer1.nitwarangal.nitw.edu:8051
      - CORE_PEER_LISTENADDRESS=0.0.0.0:8051
      - CORE_PEER_CHAINCODEADDRESS=peer1.nitwarangal.nitw.edu:8052
      # ... other config
    ports:
      - 8051:8051
```

### Configure External Access

For production deployment with external access:

1. Update `docker-compose-net.yaml` with public IPs
2. Configure firewall rules
3. Set up reverse proxy (Nginx)
4. Enable SSL/TLS certificates
5. Configure DNS records

---

## 📊 Monitoring & Maintenance

### View Logs

```bash
# View all logs
docker-compose -f docker/docker-compose-net.yaml logs -f

# View specific container
docker logs -f peer0.nitwarangal.nitw.edu

# View chaincode logs
docker logs -f $(docker ps -q --filter name=academic-records)

# Backend logs
tail -f backend/logs/backend.log

# Frontend logs (console)
# Open browser console (F12)
```

### Check Network Health

```bash
# Container status
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Resource usage
docker stats

# Disk usage
docker system df

# Network connectivity
docker network inspect nit-warangal-network_default
```

### Backup Data

```bash
# Backup ledger data
docker exec peer0.nitwarangal.nitw.edu tar czf /tmp/ledger-backup.tar.gz \
  /var/hyperledger/production

docker cp peer0.nitwarangal.nitw.edu:/tmp/ledger-backup.tar.gz \
  ./backups/ledger-$(date +%Y%m%d).tar.gz

# Backup CouchDB
docker exec couchdb0 curl -X POST http://admin:adminpw@localhost:5984/_replicate \
  -H "Content-Type: application/json" \
  -d '{"source":"academic-records-channel_academic-records","target":"backup-db","create_target":true}'
```

---

## 🎓 Next Steps

After successful setup:

1. ✅ **Explore the Application**: Test all features
2. ✅ **Read Architecture**: Understand system design (ARCHITECTURE.md)
3. ✅ **Review Chaincode**: Study smart contract code
4. ✅ **Customize**: Modify for your use case
5. ✅ **Deploy to Production**: Follow production deployment guide
6. ✅ **Integrate**: Connect with existing systems
7. ✅ **Monitor**: Set up monitoring and alerts

---

## 📞 Support

If you encounter issues:

1. Check [Common Issues](#common-issues) section
2. Review logs for error messages
3. Search GitHub Issues
4. Create a new issue with:
   - Error message
   - Steps to reproduce
   - System information
   - Logs

---

**Congratulations! You have successfully set up the NIT Warangal Academic Records Blockchain Network! 🎉**
