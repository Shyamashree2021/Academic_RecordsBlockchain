#!/bin/bash
# =================================================================
#  Academic Records - Quick Start Script
#  Purpose: Start backend and frontend (assumes network is running)
# =================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }

cd "$(dirname "$0")"

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}🚀 Quick Start - Backend & Frontend${NC}"
echo -e "${BLUE}======================================================${NC}"
echo ""

# Check network
if ! docker ps | grep -q "peer0.nitwarangal.nitw.edu"; then
    print_error "Network is not running!"
    echo ""
    echo "Please start the network first:"
    echo "  ./network.sh up"
    echo ""
    echo "Or use the full startup script:"
    echo "  ./start-all.sh"
    exit 1
fi
print_success "Network is running"

# ============================================================
# Start Backend
# ============================================================
echo ""
print_info "Starting Backend..."
cd backend

# Import admin identity
print_info "Importing admin identity..."
node src/importAdmin.js
if [ $? -ne 0 ]; then
    print_error "Failed to import admin identity"
    exit 1
fi

# Kill existing backend
lsof -ti :3000 | xargs kill -9 2>/dev/null || true
pkill -f "nodemon" 2>/dev/null || true
sleep 2

# Start backend
npm run dev > ../backend.log 2>&1 &
BACKEND_PID=$!
print_info "Backend starting (PID: $BACKEND_PID)..."
sleep 5

if curl -s --max-time 3 http://localhost:3000/health > /dev/null 2>&1; then
    print_success "Backend running on http://localhost:3000"
else
    print_error "Backend failed to start. Check backend.log"
    exit 1
fi

cd ..

# ============================================================
# Start Frontend
# ============================================================
echo ""
print_info "Starting Frontend..."
cd frontend

# Kill existing frontend
lsof -ti :4200 | xargs kill -9 2>/dev/null || true
pkill -f "ng serve" 2>/dev/null || true
sleep 2

# Start frontend
npm start > ../frontend.log 2>&1 &
FRONTEND_PID=$!
print_info "Frontend starting (PID: $FRONTEND_PID)..."
print_info "Waiting for Angular compilation (30-60 seconds)..."

for i in {1..30}; do
    if curl -s --max-time 2 http://localhost:4200 > /dev/null 2>&1; then
        print_success "Frontend running on http://localhost:4200"
        break
    fi
    sleep 2
done

cd ..

# ============================================================
# Summary
# ============================================================
echo ""
echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}✅ Services Started!${NC}"
echo -e "${GREEN}======================================================${NC}"
echo ""
echo -e "  🌐 Frontend: ${BLUE}http://localhost:4200${NC}"
echo -e "  🔧 Backend:  ${BLUE}http://localhost:3000${NC}"
echo -e "  📋 Health:   ${BLUE}http://localhost:3000/health${NC}"
echo ""
echo -e "${YELLOW}Logs:${NC}"
echo -e "  tail -f backend.log"
echo -e "  tail -f frontend.log"
echo ""
