#!/bin/bash
# =================================================================
#  Academic Records - Master Startup Script
#  Purpose: Start blockchain network, backend, and frontend
# =================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}======================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Navigate to script directory
cd "$(dirname "$0")"

print_header "🚀 Academic Records Blockchain - Complete Startup"

# ============================================================
# 1. Check if network is already running
# ============================================================
print_header "1️⃣  Checking Network Status"

if docker ps | grep -q "peer0.nitwarangal.nitw.edu"; then
    print_warning "Network is already running"
    read -p "Do you want to restart the network? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Restarting network..."
        ./network.sh clean
        ./network.sh up
        print_success "Network restarted"
    else
        print_info "Using existing network"
    fi
else
    print_info "Starting network..."
    ./network.sh up
    print_success "Network started"
fi

# ============================================================
# 2. Setup and Start Backend
# ============================================================
print_header "2️⃣  Setting Up Backend"

cd backend

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    print_info "Installing backend dependencies..."
    npm install
    print_success "Dependencies installed"
fi

# Import admin identity (required after network restart)
print_info "Importing admin identity with correct OU=admin..."
node src/importAdmin.js
if [ $? -eq 0 ]; then
    print_success "Admin identity imported"
else
    print_error "Failed to import admin identity"
    exit 1
fi

# Kill any existing backend process
print_info "Stopping any existing backend processes..."
lsof -ti :3000 | xargs kill -9 2>/dev/null || true
pkill -f "nodemon src/server.js" 2>/dev/null || true
pkill -f "node src/server.js" 2>/dev/null || true
sleep 2

# Start backend in background
print_info "Starting backend server..."
npm run dev > ../backend.log 2>&1 &
BACKEND_PID=$!

# Wait for backend to start
print_info "Waiting for backend to initialize..."
sleep 5

# Check if backend is running
if curl -s --max-time 3 http://localhost:3000/health > /dev/null 2>&1; then
    print_success "Backend running on http://localhost:3000"
    print_info "Backend PID: $BACKEND_PID"
    print_info "Backend logs: backend.log"
else
    print_error "Backend failed to start. Check backend.log for errors"
    exit 1
fi

cd ..

# ============================================================
# 3. Setup and Start Frontend
# ============================================================
print_header "3️⃣  Setting Up Frontend"

cd frontend

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    print_info "Installing frontend dependencies..."
    npm install
    print_success "Dependencies installed"
fi

# Kill any existing frontend process
print_info "Stopping any existing frontend processes..."
lsof -ti :4200 | xargs kill -9 2>/dev/null || true
pkill -f "ng serve" 2>/dev/null || true
pkill -f "angular" 2>/dev/null || true
sleep 2

# Start frontend in background
print_info "Starting frontend server..."
npm start > ../frontend.log 2>&1 &
FRONTEND_PID=$!

print_info "Waiting for frontend to compile and start..."
print_info "This may take 30-60 seconds..."

# Wait for frontend to start (Angular takes longer)
for i in {1..30}; do
    if curl -s --max-time 2 http://localhost:4200 > /dev/null 2>&1; then
        print_success "Frontend running on http://localhost:4200"
        print_info "Frontend PID: $FRONTEND_PID"
        print_info "Frontend logs: frontend.log"
        break
    fi
    if [ $i -eq 30 ]; then
        print_warning "Frontend is taking longer than expected to start"
        print_info "It may still be compiling. Check frontend.log for details"
    fi
    sleep 2
done

cd ..

# ============================================================
# 4. Summary
# ============================================================
print_header "✅ Startup Complete!"

echo ""
echo -e "${GREEN}🎉 All services are running!${NC}"
echo ""
echo -e "${BLUE}Service Status:${NC}"
echo -e "  ${GREEN}●${NC} Blockchain Network: Running"
echo -e "  ${GREEN}●${NC} Backend API: http://localhost:3000"
echo -e "  ${GREEN}●${NC} Frontend UI: http://localhost:4200"
echo ""
echo -e "${BLUE}Quick Links:${NC}"
echo -e "  📋 Backend Health: http://localhost:3000/health"
echo -e "  🌐 Application: http://localhost:4200"
echo ""
echo -e "${BLUE}Logs:${NC}"
echo -e "  Backend: tail -f backend.log"
echo -e "  Frontend: tail -f frontend.log"
echo ""
echo -e "${BLUE}To Stop Services:${NC}"
echo -e "  Backend: lsof -ti :3000 | xargs kill -9"
echo -e "  Frontend: lsof -ti :4200 | xargs kill -9"
echo -e "  Network: ./network.sh clean"
echo ""
echo -e "${YELLOW}Note: If you restart the network with './network.sh up', you MUST run:${NC}"
echo -e "  ${YELLOW}cd backend && node src/importAdmin.js${NC}"
echo ""
