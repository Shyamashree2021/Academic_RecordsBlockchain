#!/bin/bash
# =================================================================
#  Query Blockchain Script - Direct queries to Hyperledger Fabric
#  Usage: ./scripts/query-blockchain.sh <command> [args]
# =================================================================

# Set environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Add Fabric binaries to PATH
export PATH=${PROJECT_DIR}/../bin:$PATH
export FABRIC_CFG_PATH=${PROJECT_DIR}/../config

# Fabric environment variables
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="NITWarangalMSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PROJECT_DIR}/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PROJECT_DIR}/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp
export CORE_PEER_ADDRESS=localhost:7051
export CHANNEL_NAME=academic-records-channel
export CHAINCODE_NAME=academic-records

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to query and pretty print
query() {
    local description=$1
    local query_json=$2
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}🔍 Querying: ${description}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    result=$(peer chaincode query \
      -C $CHANNEL_NAME \
      -n $CHAINCODE_NAME \
      -c "$query_json" 2>&1)
    
    if [ $? -eq 0 ]; then
        echo "$result" | jq . 2>/dev/null || echo "$result"
    else
        echo -e "${YELLOW}⚠️  Error: $result${NC}"
    fi
    echo ""
}

# Show usage
show_usage() {
    echo -e "${GREEN}Blockchain Query Script${NC}"
    echo ""
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  ${BLUE}departments${NC}              - Get all departments"
    echo "  ${BLUE}department <id>${NC}          - Get specific department (e.g., CSE)"
    echo "  ${BLUE}courses <dept>${NC}           - Get courses for a department (e.g., CSE)"
    echo "  ${BLUE}course <offeringId>${NC}      - Get specific course offering"
    echo "  ${BLUE}students${NC}                 - Get all students"
    echo "  ${BLUE}student <id>${NC}             - Get specific student"
    echo "  ${BLUE}student-dept <dept>${NC}      - Get students by department"
    echo "  ${BLUE}records${NC}                  - Get all academic records"
    echo "  ${BLUE}record <id>${NC}              - Get specific academic record"
    echo "  ${BLUE}student-records <id>${NC}     - Get student's academic records"
    echo "  ${BLUE}records-dept <dept>${NC}      - Get records by department"
    echo "  ${BLUE}pending-records${NC}          - Get pending academic records"
    echo "  ${BLUE}certificates${NC}             - Get all certificates"
    echo "  ${BLUE}certificate <id>${NC}         - Get specific certificate"
    echo "  ${BLUE}student-certs <id>${NC}       - Get student's certificates"
    echo "  ${BLUE}verify-cert <id> <hash>${NC}  - Verify certificate"
    echo ""
    echo "Examples:"
    echo "  $0 departments"
    echo "  $0 department CSE"
    echo "  $0 courses CSE"
    echo "  $0 students"
    echo "  $0 student-dept CSE"
    echo ""
}

# Main logic
case "$1" in
  # Department queries
  departments)
    query "All Departments" '{"function":"GetAllDepartments","Args":[]}'
    ;;
  department)
    if [ -z "$2" ]; then
      echo "Error: Please provide department ID"
      echo "Usage: $0 department <id>"
      exit 1
    fi
    query "Department: $2" "{\"function\":\"GetDepartment\",\"Args\":[\"$2\"]}"
    ;;
  
  # Course queries
  courses)
    if [ -z "$2" ]; then
      echo "Error: Please provide department ID"
      echo "Usage: $0 courses <dept>"
      exit 1
    fi
    query "Courses for Department: $2" "{\"function\":\"GetCoursesByDepartment\",\"Args\":[\"$2\"]}"
    ;;
  course)
    if [ -z "$2" ]; then
      echo "Error: Please provide course offering ID"
      echo "Usage: $0 course <offeringId>"
      exit 1
    fi
    query "Course Offering: $2" "{\"function\":\"GetCourseOffering\",\"Args\":[\"$2\"]}"
    ;;
  
  # Student queries
  students)
    query "All Students" '{"function":"GetAllStudents","Args":[]}'
    ;;
  student)
    if [ -z "$2" ]; then
      echo "Error: Please provide student ID"
      echo "Usage: $0 student <id>"
      exit 1
    fi
    query "Student: $2" "{\"function\":\"GetStudent\",\"Args\":[\"$2\"]}"
    ;;
  student-dept)
    if [ -z "$2" ]; then
      echo "Error: Please provide department ID"
      echo "Usage: $0 student-dept <dept>"
      exit 1
    fi
    query "Students in Department: $2" "{\"function\":\"GetStudentsByDepartment\",\"Args\":[\"$2\"]}"
    ;;
  
  # Academic Record queries
  records)
    query "All Academic Records" '{"function":"GetAllAcademicRecords","Args":[]}'
    ;;
  record)
    if [ -z "$2" ]; then
      echo "Error: Please provide record ID"
      echo "Usage: $0 record <id>"
      exit 1
    fi
    query "Academic Record: $2" "{\"function\":\"GetAcademicRecord\",\"Args\":[\"$2\"]}"
    ;;
  student-records)
    if [ -z "$2" ]; then
      echo "Error: Please provide student ID"
      echo "Usage: $0 student-records <id>"
      exit 1
    fi
    query "Academic Records for Student: $2" "{\"function\":\"GetStudentRecords\",\"Args\":[\"$2\"]}"
    ;;
  records-dept)
    if [ -z "$2" ]; then
      echo "Error: Please provide department ID"
      echo "Usage: $0 records-dept <dept>"
      exit 1
    fi
    query "Records for Department: $2" "{\"function\":\"GetRecordsByDepartment\",\"Args\":[\"$2\"]}"
    ;;
  pending-records)
    query "Pending Academic Records" '{"function":"GetPendingRecords","Args":[]}'
    ;;
  
  # Certificate queries
  certificates)
    query "All Certificates" '{"function":"GetAllCertificates","Args":[]}'
    ;;
  certificate)
    if [ -z "$2" ]; then
      echo "Error: Please provide certificate ID"
      echo "Usage: $0 certificate <id>"
      exit 1
    fi
    query "Certificate: $2" "{\"function\":\"GetCertificate\",\"Args\":[\"$2\"]}"
    ;;
  student-certs)
    if [ -z "$2" ]; then
      echo "Error: Please provide student ID"
      echo "Usage: $0 student-certs <id>"
      exit 1
    fi
    query "Certificates for Student: $2" "{\"function\":\"GetStudentCertificates\",\"Args\":[\"$2\"]}"
    ;;
  verify-cert)
    if [ -z "$2" ] || [ -z "$3" ]; then
      echo "Error: Please provide certificate ID and PDF hash"
      echo "Usage: $0 verify-cert <id> <hash>"
      exit 1
    fi
    query "Verify Certificate: $2" "{\"function\":\"VerifyCertificate\",\"Args\":[\"$2\",\"$3\"]}"
    ;;
  
  # Help
  -h|--help|help)
    show_usage
    ;;
  
  *)
    if [ -z "$1" ]; then
      show_usage
    else
      echo "Error: Unknown command '$1'"
      echo ""
      show_usage
    fi
    exit 1
    ;;
esac
