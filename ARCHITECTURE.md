# NIT Warangal Academic Records - Architecture Documentation

> **Comprehensive Technical Architecture and Design Patterns**

---

## 📋 Table of Contents

- [System Overview](#system-overview)
- [Network Architecture](#network-architecture)
- [Chaincode Architecture](#chaincode-architecture)
- [Data Models](#data-models)
- [Transaction Flows](#transaction-flows)
- [Security Architecture](#security-architecture)
- [Performance & Scalability](#performance--scalability)
- [Deployment Architecture](#deployment-architecture)

---

## 🎯 System Overview

### Purpose

The NIT Warangal Academic Records Blockchain Network is designed to:

1. **Immutable Record Keeping**: Store academic records that cannot be tampered with
2. **Decentralized Verification**: Enable multiple organizations to verify credentials
3. **Privacy Protection**: Protect sensitive student data using Private Data Collections
4. **Automated Workflows**: Implement business logic through smart contracts
5. **Audit Trail**: Maintain complete history of all academic transactions

### Technology Stack

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
├─────────────────────────────────────────────────────────┤
│  Frontend: Angular 17 + Material Design                 │
│  Backend: Node.js + Express + Fabric SDK                │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────▼─────────────────────────────┐
│                  Blockchain Layer                       │
├─────────────────────────────────────────────────────────┤
│  Platform: Hyperledger Fabric 2.5                      │
│  Chaincode: Go (Golang) 1.21                           │
│  State DB: CouchDB 3.x                                 │
│  Consensus: Raft (via Orderer)                         │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────▼─────────────────────────────┐
│                Infrastructure Layer                     │
├─────────────────────────────────────────────────────────┤
│  Containers: Docker + Docker Compose                   │
│  Networking: Docker Bridge Network                     │
│  Storage: Docker Volumes                               │
└─────────────────────────────────────────────────────────┘
```

---

## 🏗️ Network Architecture

### 1. Organizations

The network consists of three member organizations:

#### NITWarangal Organization (NITWarangalMSP)

**Purpose**: Main academic institution managing student records

**Components**:
- **Peer**: peer0.nitwarangal.nitw.edu:7051
- **CouchDB**: couchdb0:5984
- **CA**: ca.nitwarangal.nitw.edu:7054
- **Domain**: nitwarangal.nitw.edu

**Actors**:
- **Admin**: Full system access, user management
- **Dean**: Academic policy enforcement
- **Registrar**: Record management
- **Students**: Self-service access

**Responsibilities**:
- Student enrollment
- Record approval/rejection
- Certificate issuance
- Policy enforcement

#### Departments Organization (DepartmentsMSP)

**Purpose**: Department-level academic operations

**Components**:
- **Peer**: peer0.departments.nitw.edu:9051
- **CouchDB**: couchdb1:6984
- **CA**: ca.departments.nitw.edu:8054
- **Domain**: departments.nitw.edu

**Departments**:
- Computer Science & Engineering (CSE)
- Electronics & Communication Engineering (ECE)
- Mechanical Engineering (MECH)
- Civil Engineering (CIVIL)

**Actors**:
- **Department Heads**: Department management
- **Faculty**: Course instruction, grade submission
- **Staff**: Administrative support

**Responsibilities**:
- Course management
- Grade submission
- Department-specific policies
- Faculty management

#### Verifiers Organization (VerifiersMSP)

**Purpose**: External credential verification

**Components**:
- **Peer**: peer0.verifiers.nitw.edu:11051
- **CouchDB**: couchdb2:8984
- **CA**: ca.verifiers.nitw.edu:9054
- **Domain**: verifiers.nitw.edu

**Actors**:
- **Employers**: Verify candidate credentials
- **Universities**: Verify transfer students
- **Government Agencies**: Verify for official purposes

**Responsibilities**:
- Credential verification
- Public record queries
- Authentication checks

### 2. Orderer Service

**Type**: Raft-based ordering service

**Configuration**:
- **Address**: orderer.nitw.edu:7050
- **Admin Port**: 7053 (for channel management)
- **Consensus**: Raft (single orderer for development)
- **Domain**: nitw.edu

**Responsibilities**:
- Transaction ordering
- Block creation
- Channel management
- Consensus coordination

**Production Considerations**:
```yaml
# For production, use 3 or 5 orderers for fault tolerance
orderer1.nitw.edu:7050
orderer2.nitw.edu:8050
orderer3.nitw.edu:9050
```

### 3. Certificate Authorities

Each organization has its own CA for identity management:

| CA | Port | Purpose | Identities |
|----|------|---------|-----------|
| ca_orderer | 7054 | Orderer identities | Orderer admin, orderer node |
| ca_nitwarangal | 7054 | NITWarangal identities | Admin, students, registrar |
| ca_departments | 8054 | Department identities | Faculty, dept heads, staff |
| ca_verifiers | 9054 | Verifier identities | Employers, universities |

**CA Features**:
- X.509 certificate issuance
- Identity enrollment and registration
- Certificate revocation
- Attribute-based certificates (for ABAC)

### 4. Channel Configuration

**Channel Name**: `academic-records-channel`

**Member Organizations**:
- NITWarangalMSP (Admin)
- DepartmentsMSP
- VerifiersMSP

**Channel Policies**:

```yaml
Policies:
  Readers:
    Type: ImplicitMeta
    Rule: "ANY Readers"  # Any org member can read
  
  Writers:
    Type: ImplicitMeta
    Rule: "ANY Writers"  # Any org member can write
  
  Admins:
    Type: ImplicitMeta
    Rule: "MAJORITY Admins"  # Majority of org admins
  
  Endorsement:
    Type: ImplicitMeta
    Rule: "MAJORITY Endorsement"  # Majority endorsement required
```

**Application Capabilities**:
- V2_5 (Hyperledger Fabric 2.5 features)
- Private Data Collections
- Chaincode lifecycle
- Implicit collections

### 5. Network Topology Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                        Docker Network                               │
│                  (nit-warangal-network_default)                     │
└────────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │                                               │
┌───────▼────────┐                             ┌───────▼────────┐
│  Orderer Node  │                             │   CLI Tool     │
│ orderer.nitw   │◄────────────────────────────│  (Testing)     │
│ edu:7050       │     Admin Channel Join      │                │
└───────┬────────┘                             └────────────────┘
        │
        │ Raft Consensus / Block Delivery
        │
        ├─────────────────┬─────────────────┬─────────────────┐
        │                 │                 │                 │
┌───────▼────────┐ ┌──────▼───────┐ ┌──────▼───────┐ ┌──────▼────────┐
│ NITWarangal    │ │ Departments  │ │  Verifiers   │ │ Fabric CAs    │
│ Peer Network   │ │ Peer Network │ │ Peer Network │ │ (4 instances) │
├────────────────┤ ├──────────────┤ ├──────────────┤ ├───────────────┤
│ peer0:7051     │ │ peer0:9051   │ │ peer0:11051  │ │ ca_orderer    │
│ couchdb0:5984  │ │ couchdb1:6984│ │ couchdb2:8984│ │ ca_nitwarangal│
│ ca:7054        │ │ ca:8054      │ │ ca:9054      │ │ ca_departments│
│                │ │              │ │              │ │ ca_verifiers  │
└────────────────┘ └──────────────┘ └──────────────┘ └───────────────┘
```

---

## 🧩 Chaincode Architecture

### Chaincode Structure

**Name**: `academic-records`  
**Version**: 2.0  
**Language**: Go (Golang)  
**Package**: `github.com/hyperledger/fabric-samples/chaincode-go/academic-records`

### Core Components

```go
// Main Chaincode Structure
type AcademicRecordsChaincode struct {
    contractapi.Contract
}

// Data Models
type Student struct {
    StudentID       string
    Name            string
    Department      string
    Batch           string
    Email           string
    Category        string
    EnrollmentDate  string
    Status          string
}

type StudentPrivateDetails struct {
    StudentID     string
    AadhaarHash   string
    Phone         string
    PersonalEmail string
}

type AcademicRecord struct {
    RecordID      string
    StudentID     string
    Year          string
    Semester      string
    SGPA          float64
    Credits       int
    Status        string
    SubmittedBy   string
    ApprovedBy    string
    Timestamp     string
}

type Course struct {
    CourseID      string
    CourseName    string
    Department    string
    Credits       int
    Faculty       string
    Semester      string
}

type Department struct {
    DepartmentID  string
    Name          string
    HeadName      string
    Email         string
}

type Certificate struct {
    CertificateID string
    StudentID     string
    Type          string
    IssueDate     string
    ValidUntil    string
    IssuedBy      string
    VerificationHash string
}
```

### Chaincode Functions

#### Student Management

| Function | Parameters | Purpose | Access Control |
|----------|-----------|---------|----------------|
| `CreateStudent` | studentID, name, dept, batch, email, category | Create new student record | Admin only |
| `GetStudent` | studentID | Get public student details | Any authenticated user |
| `GetAllStudents` | - | Get all students | Admin, Faculty |
| `UpdateStudent` | studentID, updates | Update student info | Admin only |
| `GetStudentsByDepartment` | department | Query by department | Faculty, Admin |
| `StudentExists` | studentID | Check if student exists | Any authenticated user |

#### Private Data Management

| Function | Parameters | Purpose | Access Control |
|----------|-----------|---------|----------------|
| `GetStudentPrivateDetails` | studentID | Get private student data | Admin, Owner only |
| `UpdateStudentPrivateDetails` | studentID, private data | Update private info | Admin, Owner only |

#### Academic Records

| Function | Parameters | Purpose | Access Control |
|----------|-----------|---------|----------------|
| `SubmitAcademicRecord` | studentID, year, sem, sgpa, credits, status | Submit semester grades | Faculty, Admin |
| `GetAcademicRecord` | recordID | Get specific record | Authenticated users |
| `GetStudentAcademicHistory` | studentID | Get all records for student | Student (own), Admin, Faculty |
| `ApproveAcademicRecord` | recordID | Approve submitted record | Admin only |
| `RejectAcademicRecord` | recordID, reason | Reject record | Admin only |
| `QueryPendingRecords` | - | Get all pending approvals | Admin, Faculty |

#### Course Management

| Function | Parameters | Purpose | Access Control |
|----------|-----------|---------|----------------|
| `CreateCourse` | courseID, name, dept, credits, faculty, sem | Create new course | Admin, Dept Head |
| `GetCourse` | courseID | Get course details | Any authenticated user |
| `GetCoursesByDepartment` | department | Query courses by dept | Any authenticated user |
| `UpdateCourse` | courseID, updates | Update course info | Admin, Dept Head |
| `DeleteCourse` | courseID | Remove course | Admin only |

#### Department Management

| Function | Parameters | Purpose | Access Control |
|----------|-----------|---------|----------------|
| `CreateDepartment` | deptID, name, head, email | Create department | Admin only |
| `GetDepartment` | deptID | Get department details | Any authenticated user |
| `GetAllDepartments` | - | List all departments | Any authenticated user |
| `UpdateDepartment` | deptID, updates | Update department | Admin only |

#### Certificate Management

| Function | Parameters | Purpose | Access Control |
|----------|-----------|---------|----------------|
| `IssueCertificate` | studentID, type | Issue certificate | Admin only |
| `GetCertificate` | certificateID | Get certificate details | Owner, Verifier, Admin |
| `VerifyCertificate` | certificateID, hash | Verify certificate authenticity | Verifier, Any |
| `GetStudentCertificates` | studentID | Get all student certificates | Owner, Admin |
| `RevokeCertificate` | certificateID | Revoke certificate | Admin only |

### Endorsement Policy

**Policy**: OR('NITWarangalMSP.peer', 'DepartmentsMSP.peer', 'VerifiersMSP.peer')

**Meaning**: Any single peer from any organization can endorse a transaction.

**Production Recommendation**:
```
AND(
  OR('NITWarangalMSP.peer', 'DepartmentsMSP.peer'),
  'VerifiersMSP.peer'
)
```
This requires endorsement from at least two organizations.

### Private Data Collections

**Collection**: `studentPrivateDetails`

**Configuration**:
```json
{
  "name": "studentPrivateDetails",
  "policy": "OR('NITWarangalMSP.member', 'DepartmentsMSP.member')",
  "requiredPeerCount": 1,
  "maxPeerCount": 2,
  "blockToLive": 0,
  "memberOnlyRead": true,
  "memberOnlyWrite": true,
  "endorsementPolicy": {
    "signaturePolicy": "OR('NITWarangalMSP.member', 'DepartmentsMSP.member')"
  }
}
```

**Private Data Fields**:
- Aadhaar Hash (SHA-256)
- Phone Number
- Personal Email

**Access**:
- NITWarangal: Full access
- Departments: Full access
- Verifiers: No access

---

## 📊 Data Models

### 1. Student Model

```json
{
  "studentID": "CS21B001",
  "name": "John Doe",
  "department": "CSE",
  "batch": "2021",
  "email": "[email protected]",
  "category": "GENERAL",
  "enrollmentDate": "2021-08-01T00:00:00Z",
  "status": "Active",
  "docType": "student"
}
```

**Private Collection**:
```json
{
  "studentID": "CS21B001",
  "aadhaarHash": "sha256_hash_of_aadhaar",
  "phone": "9876543210",
  "personalEmail": "[email protected]"
}
```

### 2. Academic Record Model

```json
{
  "recordID": "REC-CS21B001-2021-1",
  "studentID": "CS21B001",
  "year": "2021",
  "semester": "1",
  "sgpa": 8.5,
  "credits": 20,
  "status": "Approved",
  "submittedBy": "faculty1",
  "submittedDate": "2022-01-15T10:30:00Z",
  "approvedBy": "admin",
  "approvedDate": "2022-01-16T14:20:00Z",
  "remarks": "",
  "docType": "academicRecord"
}
```

### 3. Course Model

```json
{
  "courseID": "CSE101",
  "courseName": "Introduction to Programming",
  "department": "CSE",
  "credits": 4,
  "faculty": "Dr. Smith",
  "semester": "1",
  "description": "Fundamentals of programming",
  "docType": "course"
}
```

### 4. Department Model

```json
{
  "departmentID": "CSE",
  "name": "Computer Science & Engineering",
  "headName": "Prof. Kumar",
  "email": "[email protected]",
  "phone": "040-12345678",
  "establishedYear": "1959",
  "docType": "department"
}
```

### 5. Certificate Model

```json
{
  "certificateID": "CERT-CS21B001-2025-DEGREE",
  "studentID": "CS21B001",
  "type": "Degree Certificate",
  "issueDate": "2025-06-01T00:00:00Z",
  "validUntil": "2035-06-01T00:00:00Z",
  "issuedBy": "admin",
  "verificationHash": "sha256_hash_of_certificate_data",
  "metadata": {
    "cgpa": 8.5,
    "degree": "B.Tech",
    "department": "CSE"
  },
  "docType": "certificate"
}
```

### CouchDB Indexes

For efficient querying, the following indexes are created:

```json
{
  "index": {
    "fields": ["docType", "department"]
  },
  "ddoc": "indexDeptDoc",
  "name": "indexDept",
  "type": "json"
}

{
  "index": {
    "fields": ["docType", "studentID"]
  },
  "ddoc": "indexStudentDoc",
  "name": "indexStudent",
  "type": "json"
}

{
  "index": {
    "fields": ["docType", "status"]
  },
  "ddoc": "indexStatusDoc",
  "name": "indexStatus",
  "type": "json"
}
```

---

## 🔄 Transaction Flows

### Flow 1: Student Enrollment

```
┌─────────┐      ┌─────────┐      ┌──────────┐      ┌────────┐
│ Admin   │      │ Backend │      │  Peer    │      │ Ledger │
│ (Web)   │      │   API   │      │ (NITW)   │      │(CouchDB│
└────┬────┘      └────┬────┘      └────┬─────┘      └───┬────┘
     │                │                 │                │
     │ 1. Submit      │                 │                │
     │ Student Form   │                 │                │
     ├───────────────>│                 │                │
     │                │                 │                │
     │                │ 2. Validate     │                │
     │                │    Identity     │                │
     │                │ (JWT Token)     │                │
     │                │                 │                │
     │                │ 3. Invoke       │                │
     │                │    CreateStudent│                │
     │                ├────────────────>│                │
     │                │                 │                │
     │                │                 │ 4. Execute     │
     │                │                 │    Chaincode   │
     │                │                 │                │
     │                │                 │ 5. Write to    │
     │                │                 │    State DB    │
     │                │                 ├───────────────>│
     │                │                 │                │
     │                │ 6. Response     │                │
     │                │<────────────────┤                │
     │                │                 │                │
     │ 7. Success     │                 │                │
     │<───────────────┤                 │                │
     │                │                 │                │
```

**Steps**:
1. Admin fills student enrollment form
2. Backend validates JWT token and admin role
3. Backend invokes `CreateStudent` chaincode function
4. Chaincode validates input and checks ABAC permissions
5. Student data written to ledger (public data on all peers)
6. Private data (Aadhaar, phone) written to private collection
7. Transaction response returned to admin
8. Block committed to all peers

### Flow 2: Academic Record Submission & Approval

```
┌─────────┐  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌─────────┐
│ Faculty │  │ Backend │  │  Peer    │  │ Ledger │  │  Admin  │
└────┬────┘  └────┬────┘  └────┬─────┘  └───┬────┘  └────┬────┘
     │            │             │            │            │
     │ 1. Submit  │             │            │            │
     │    Grades  │             │            │            │
     ├───────────>│             │            │            │
     │            │             │            │            │
     │            │ 2. Invoke   │            │            │
     │            │ SubmitRecord│            │            │
     │            ├────────────>│            │            │
     │            │             │            │            │
     │            │             │ 3. Create  │            │
     │            │             │   Record   │            │
     │            │             │   (Pending)│            │
     │            │             ├───────────>│            │
     │            │             │            │            │
     │            │ 4. Success  │            │            │
     │<───────────┤<────────────┤            │            │
     │            │             │            │            │
     │            │             │            │ 5. Query   │
     │            │             │            │   Pending  │
     │            │             │            │<───────────┤
     │            │             │            │            │
     │            │             │            │ 6. Return  │
     │            │             │            │   Records  │
     │            │             │            ├───────────>│
     │            │             │            │            │
     │            │             │ 7. Approve │            │
     │            │             │<───────────┼────────────┤
     │            │             │            │            │
     │            │             │ 8. Update  │            │
     │            │             │   Status   │            │
     │            │             ├───────────>│            │
     │            │             │            │            │
```

**Steps**:
1. Faculty submits semester grades for student
2. Backend invokes `SubmitAcademicRecord`
3. Record created with status "Pending"
4. Faculty receives success confirmation
5. Admin queries pending records
6. System returns list of pending approvals
7. Admin reviews and approves record
8. Record status updated to "Approved"
9. Student can now view approved grades

### Flow 3: Certificate Issuance & Verification

```
┌─────────┐  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐
│ Student │  │  Admin  │  │  Ledger  │  │Verifier │  │ Employer │
└────┬────┘  └────┬────┘  └────┬─────┘  └────┬────┘  └────┬─────┘
     │            │             │             │             │
     │ 1. Request │             │             │             │
     │ Certificate│             │             │             │
     ├───────────>│             │             │             │
     │            │             │             │             │
     │            │ 2. Verify   │             │             │
     │            │    Eligiblty│             │             │
     │            │    (CGPA,   │             │             │
     │            │     Credits)│             │             │
     │            │             │             │             │
     │            │ 3. Issue    │             │             │
     │            │ Certificate │             │             │
     │            ├────────────>│             │             │
     │            │             │             │             │
     │            │             │ 4. Generate │             │
     │            │             │    Hash     │             │
     │            │             │             │             │
     │ 5. Receive │             │             │             │
     │ Certificate│             │             │             │
     │<───────────┤             │             │             │
     │            │             │             │             │
     │ 6. Share Certificate ID & Hash          │             │
     │──────────────────────────────────────────────────────>│
     │            │             │             │             │
     │            │             │             │ 7. Verify   │
     │            │             │             │<────────────┤
     │            │             │             │             │
     │            │             │ 8. Query    │             │
     │            │             │<────────────┤             │
     │            │             │             │             │
     │            │             │ 9. Return   │             │
     │            │             │    & Verify │             │
     │            │             │    Hash     │             │
     │            │             ├────────────>│             │
     │            │             │             │             │
     │            │             │             │10. Verified │
     │            │             │             │    Response │
     │            │             │             ├────────────>│
     │            │             │             │             │
```

**Steps**:
1. Student requests certificate through portal
2. Admin verifies eligibility (completion, credits, grades)
3. Admin invokes `IssueCertificate` chaincode
4. System generates certificate with verification hash
5. Student receives certificate ID and download link
6. Student shares certificate ID with employer
7. Employer's verifier accesses blockchain
8. Verifier queries certificate using certificate ID
9. System returns certificate details and hash
10. Employer verifies authenticity by matching hash
11. Verified confirmation displayed

### Flow 4: External Verification (Read-Only)

```
┌──────────┐      ┌─────────┐      ┌──────────┐      ┌────────┐
│ Employer │      │ Verifier│      │  Peer    │      │ Ledger │
│          │      │  Portal │      │(Verifier)│      │        │
└────┬─────┘      └────┬────┘      └────┬─────┘      └───┬────┘
     │                 │                 │                │
     │ 1. Enter        │                 │                │
     │ Student ID      │                 │                │
     ├────────────────>│                 │                │
     │                 │                 │                │
     │                 │ 2. Authenticate │                │
     │                 │    (Verifier    │                │
     │                 │     Identity)   │                │
     │                 │                 │                │
     │                 │ 3. Query        │                │
     │                 │    GetStudent   │                │
     │                 ├────────────────>│                │
     │                 │                 │                │
     │                 │                 │ 4. Read Public │
     │                 │                 │    Data Only   │
     │                 │                 ├───────────────>│
     │                 │                 │                │
     │                 │ 5. Response     │                │
     │                 │   (No Private   │                │
     │                 │    Data)        │                │
     │                 │<────────────────┤                │
     │                 │                 │                │
     │ 6. Display      │                 │                │
     │    Verified     │                 │                │
     │    Info         │                 │                │
     │<────────────────┤                 │                │
     │                 │                 │                │
```

**Key Points**:
- Verifiers can only access public student data
- No access to private data collections
- Read-only operations (queries, no invokes)
- Certificate verification by hash matching

---

## 🔐 Security Architecture

### 1. Identity Management

**Fabric CA Features**:
- X.509 certificate issuance
- Enrollment and registration
- Attribute-based certificates
- Certificate revocation lists (CRL)

**Identity Hierarchy**:
```
Root CA (ca.nitw.edu)
├── Orderer Org (OrdererMSP)
│   ├── Admin@nitw.edu
│   └── orderer.nitw.edu
│
├── NITWarangal Org (NITWarangalMSP)
│   ├── Admin@nitwarangal.nitw.edu
│   ├── User1@nitwarangal.nitw.edu (Student)
│   └── peer0.nitwarangal.nitw.edu
│
├── Departments Org (DepartmentsMSP)
│   ├── Admin@departments.nitw.edu
│   ├── User1@departments.nitw.edu (Faculty)
│   └── peer0.departments.nitw.edu
│
└── Verifiers Org (VerifiersMSP)
    ├── Admin@verifiers.nitw.edu
    ├── User1@verifiers.nitw.edu (Employer)
    └── peer0.verifiers.nitw.edu
```

### 2. Attribute-Based Access Control (ABAC)

**Attributes in Certificates**:
```go
// Example certificate attributes
type UserAttributes struct {
    Role        string  // "admin", "faculty", "student", "verifier"
    Department  string  // "CSE", "ECE", "MECH", "CIVIL"
    Permissions []string // ["read", "write", "approve"]
}
```

**ABAC Implementation in Chaincode**:
```go
func (c *AcademicRecordsChaincode) CreateStudent(ctx contractapi.TransactionContextInterface, ...) error {
    // Get client identity
    clientID, err := ctx.GetClientIdentity()
    
    // Check role attribute
    role, found, err := clientID.GetAttributeValue("role")
    if !found || role != "admin" {
        return fmt.Errorf("Access denied: Only admins can create students")
    }
    
    // Proceed with student creation
    // ...
}
```

### 3. Private Data Collections (PDC)

**Configuration**:
```json
{
  "name": "studentPrivateDetails",
  "policy": "OR('NITWarangalMSP.member', 'DepartmentsMSP.member')",
  "requiredPeerCount": 1,
  "maxPeerCount": 2,
  "blockToLive": 0,
  "memberOnlyRead": true,
  "memberOnlyWrite": true
}
```

**How It Works**:
1. Private data sent via transient field (not in transaction)
2. Hash of private data stored on ledger (public)
3. Actual private data stored only on authorized peers
4. Gossip protocol distributes to authorized peers only

**Benefits**:
- Sensitive data not visible to unauthorized orgs
- Data still participates in transaction validation
- Verifiable without revealing actual data

### 4. TLS Communication

**TLS Configuration**:
- Peer-to-peer communication encrypted
- Client-to-peer communication encrypted
- Orderer-to-peer communication encrypted
- Mutual TLS authentication

**Certificate Types**:
- TLS CA certificates
- TLS server certificates
- TLS client certificates

### 5. Endorsement Policies

**Current Policy**:
```
OR('NITWarangalMSP.peer', 'DepartmentsMSP.peer', 'VerifiersMSP.peer')
```

**Production Recommendation**:
```
AND(
  OR('NITWarangalMSP.peer', 'DepartmentsMSP.peer'),
  'VerifiersMSP.peer'
)
```

This requires at least two organizations to endorse.

### 6. Channel Policies

**Read Policy**: ANY Readers (any member can read)  
**Write Policy**: ANY Writers (any member can write)  
**Admin Policy**: MAJORITY Admins (majority of admins required)  
**Endorsement Policy**: MAJORITY Endorsement (majority required)

---

## ⚡ Performance & Scalability

### Current Configuration

| Component | Specification | Capacity |
|-----------|--------------|----------|
| Peers | 3 (1 per org) | ~1000 TPS total |
| Orderer | 1 (Raft) | ~300 TPS |
| CouchDB | 3 instances | ~100 queries/sec per instance |
| Block Size | 10 transactions | Configurable |
| Block Timeout | 2 seconds | Configurable |

### Scalability Strategies

#### 1. Horizontal Scaling

**Add More Peers per Organization**:
```yaml
# Current
peer0.nitwarangal.nitw.edu

# Scaled
peer0.nitwarangal.nitw.edu
peer1.nitwarangal.nitw.edu
peer2.nitwarangal.nitw.edu
```

**Benefits**:
- Increased transaction throughput
- Better fault tolerance
- Load distribution

#### 2. Orderer Scaling

**Raft Cluster**:
```yaml
# Production setup (5 orderers)
orderer1.nitw.edu:7050
orderer2.nitw.edu:8050
orderer3.nitw.edu:9050
orderer4.nitw.edu:10050
orderer5.nitw.edu:11050
```

**Benefits**:
- Byzantine fault tolerance (BFT)
- Can tolerate (n-1)/2 failures
- Higher throughput

#### 3. Channel Partitioning

**Multiple Channels Strategy**:
```
academic-records-channel (current)
├── All three orgs

certificate-channel (new)
├── NITWarangal + Verifiers only

departmental-channel (new)
├── Departments + NITWarangal only
```

**Benefits**:
- Reduced ledger size per peer
- Better privacy
- Improved performance

#### 4. State Database Optimization

**CouchDB Indexes**:
- Create indexes on frequently queried fields
- Use pagination for large result sets
- Implement caching layer

**Example**:
```javascript
// Paginated query
{
  "selector": { "docType": "student" },
  "limit": 50,
  "skip": 0,
  "use_index": ["indexStudentDoc", "indexStudent"]
}
```

### Performance Benchmarks

**Expected Performance** (Current Setup):

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Create Student | ~300ms | ~10 TPS |
| Query Student | ~50ms | ~100 TPS |
| Submit Record | ~400ms | ~8 TPS |
| Approve Record | ~400ms | ~8 TPS |
| Issue Certificate | ~500ms | ~6 TPS |

**Production Optimized** (With scaling):

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Create Student | ~150ms | ~50 TPS |
| Query Student | ~20ms | ~500 TPS |
| Submit Record | ~200ms | ~40 TPS |
| Approve Record | ~200ms | ~40 TPS |
| Issue Certificate | ~250ms | ~30 TPS |

---

## 🚀 Deployment Architecture

### Development Environment

**Current Setup** (Docker Compose):
```
Single Host Machine
├── 10+ Docker Containers
│   ├── Orderer (1)
│   ├── Peers (3)
│   ├── CouchDB (3)
│   ├── Fabric CA (4)
│   └── CLI (1)
├── Backend API (Node.js)
└── Frontend App (Angular)
```

### Production Deployment

**Recommended: Kubernetes Deployment**

```yaml
Kubernetes Cluster
├── Namespace: nitw-blockchain
│   ├── StatefulSet: Orderers (3-5 replicas)
│   ├── StatefulSet: NITWarangal Peers (2 replicas)
│   ├── StatefulSet: Departments Peers (2 replicas)
│   ├── StatefulSet: Verifiers Peers (2 replicas)
│   ├── Deployment: CouchDB (6 replicas)
│   ├── Deployment: Fabric CAs (4 replicas)
│   ├── Service: LoadBalancer (External access)
│   └── PersistentVolumes: Ledger storage
│
├── Namespace: nitw-backend
│   ├── Deployment: Backend API (3 replicas)
│   ├── Service: LoadBalancer
│   └── HPA: Auto-scaling (2-10 pods)
│
└── Namespace: nitw-frontend
    ├── Deployment: Frontend (3 replicas)
    ├── Service: LoadBalancer
    ├── Ingress: SSL/TLS termination
    └── CDN: Static asset delivery
```

**High Availability Setup**:
- Multi-zone deployment
- Automatic failover
- Rolling updates
- Health checks and monitoring

### Monitoring & Logging

**Tools**:
- Prometheus: Metrics collection
- Grafana: Visualization
- ELK Stack: Log aggregation
- Jaeger: Distributed tracing

**Key Metrics**:
- Transaction throughput (TPS)
- Block commit time
- Endorsement latency
- Peer resource usage (CPU, memory, disk)
- Network bandwidth

---

## 📊 Disaster Recovery

### Backup Strategy

**What to Backup**:
1. **Ledger Data**: All peer ledgers
2. **State Database**: CouchDB backups
3. **Crypto Material**: CA certificates, private keys
4. **Configuration**: Channel configs, chaincode

**Backup Frequency**:
- Ledger: Continuous (WAL)
- State DB: Daily
- Crypto: Once (immutable)
- Config: On change

### Recovery Procedures

**Peer Failure**:
1. Stop failed peer
2. Replace container
3. Sync ledger from other peers
4. Resume operations

**Orderer Failure** (Raft):
- Automatic failover
- Remaining orderers continue
- Replace failed orderer
- Re-join Raft cluster

**Complete Network Failure**:
1. Restore crypto material
2. Restore orderer genesis block
3. Restore peer ledgers
4. Restore CouchDB state
5. Restart network
6. Verify integrity

---

**This architecture provides a secure, scalable, and production-ready blockchain network for academic record management.**
