package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	// studentPrivateCollection is the name of the private data collection for sensitive student data
	studentPrivateCollection = "studentPrivateCollection"
)

// SmartContract provides functions for managing academic records
type SmartContract struct {
	contractapi.Contract
}

// Student represents the public part of a student's record
type Student struct {
	StudentID          string    `json:"studentId"`
	Name               string    `json:"name"`
	Department         string    `json:"department"`
	EnrollmentYear     int       `json:"enrollmentYear"`
	RollNumber         string    `json:"rollNumber"` // Primary ID
	Email              string    `json:"email"`      // Must be @student.nitw.ac.in
	AdmissionCategory  string    `json:"admissionCategory"`
	Status             string    `json:"status"` // ACTIVE, GRADUATED, WITHDRAWN, CANCELLED, TEMPORARY_WITHDRAWAL
	TotalCreditsEarned float64   `json:"totalCreditsEarned"`
	CurrentCGPA        float64   `json:"currentCGPA"`
	CreatedBy          string    `json:"createdBy"`
	CreatedAt          time.Time `json:"createdAt"`
	ModifiedBy         string    `json:"modifiedBy"`
	ModifiedAt         time.Time `json:"modifiedAt"`
}

// StudentPrivateDetails represents the private part of a student's record
type StudentPrivateDetails struct {
	StudentID     string `json:"studentId"`
	Phone         string `json:"phone"`
	PersonalEmail string `json:"personalEmail"`
	AadhaarHash   string `json:"aadhaarHash"` // SHA256 hash of Aadhaar
}

// Department represents an academic department
type Department struct {
	DepartmentID   string    `json:"departmentId"`   // e.g., "CSE", "ECE", "ME"
	DepartmentName string    `json:"departmentName"` // e.g., "Computer Science and Engineering"
	HOD            string    `json:"hod"`            // Head of Department name
	Email          string    `json:"email"`          // Department email
	Phone          string    `json:"phone"`          // Department phone
	CreatedBy      string    `json:"createdBy"`
	CreatedAt      time.Time `json:"createdAt"`
	ModifiedBy     string    `json:"modifiedBy"`
	ModifiedAt     time.Time `json:"modifiedAt"`
}

// CourseOffering represents a course offered by department with many-to-many relationship
type CourseOffering struct {
	OfferingID   string    `json:"offeringId"`   // Unique ID: dept-course-semester-year
	DepartmentID string    `json:"departmentId"` // Department offering the course
	CourseCode   string    `json:"courseCode"`   // e.g., "CS301"
	CourseName   string    `json:"courseName"`   // e.g., "Data Structures"
	Credits      float64   `json:"credits"`      // 0.5-6 credits
	Semester     int       `json:"semester"`     // Which semester (1-8)
	AcademicYear string    `json:"academicYear"` // e.g., "2024-25"
	IsActive     bool      `json:"isActive"`     // Whether course is currently offered
	CreatedBy    string    `json:"createdBy"`
	CreatedAt    time.Time `json:"createdAt"`
	ModifiedBy   string    `json:"modifiedBy"`
	ModifiedAt   time.Time `json:"modifiedAt"`
}

// Course represents a single course in student's academic record (Enhanced with validation)
type Course struct {
	CourseCode string  `json:"courseCode"`
	CourseName string  `json:"courseName"`
	Credits    float64 `json:"credits"`    // 0.5-6 credits
	Grade      string  `json:"grade"`      // S, A, B, C, D, P, U, R
	Department string  `json:"department"` // Changed from FacultyID to Department
}

// AcademicRecord represents semester academic records (Enhanced)
type AcademicRecord struct {
	RecordID      string    `json:"recordId"`
	StudentID     string    `json:"studentId"`
	Department    string    `json:"department"` // For department-level access control
	Semester      int       `json:"semester"`
	Courses       []Course  `json:"courses"`
	TotalCredits  float64   `json:"totalCredits"`
	SGPA          float64   `json:"sgpa"`
	CGPA          float64   `json:"cgpa"`
	Timestamp     time.Time `json:"timestamp"`
	SubmittedBy   string    `json:"submittedBy"`   // Department who submitted
	ApprovedBy    string    `json:"approvedBy"`    // Admin who approved
	Status        string    `json:"status"`        // DRAFT, SUBMITTED, APPROVED
	RejectionNote string    `json:"rejectionNote"` // If sent back for corrections
}

// Certificate represents a certificate issued to a student (Enhanced)
type Certificate struct {
	CertificateID    string    `json:"certificateId"`
	StudentID        string    `json:"studentId"`
	Type             string    `json:"type"` // DEGREE, TRANSCRIPT, PROVISIONAL, BONAFIDE, MIGRATION, CHARACTER, STUDY_CONDUCT
	IssueDate        time.Time `json:"issueDate"`
	ExpiryDate       time.Time `json:"expiryDate,omitempty"` // For BONAFIDE
	PDFHash          string    `json:"pdfHash"`
	IPFSHash         string    `json:"ipfsHash"`
	IssuedBy         string    `json:"issuedBy"`
	Verified         bool      `json:"verified"`
	Revoked          bool      `json:"revoked"`
	RevokedBy        string    `json:"revokedBy"`
	RevokedAt        time.Time `json:"revokedAt"`
	RevocationReason string    `json:"revocationReason"`
	DegreeAwarded    string    `json:"degreeAwarded"` // Degree name (e.g., "B.Tech in Computer Science")
	FinalCGPA        float64   `json:"finalCGPA"`     // Final CGPA at graduation
	IsValid          bool      `json:"isValid"`       // Computed: !Revoked && (ExpiryDate.IsZero() || ExpiryDate > now)
}

// Faculty represents a faculty member's profile
type Faculty struct {
	FacultyID      string    `json:"facultyId"`
	Name           string    `json:"name"`
	Department     string    `json:"department"`
	Designation    string    `json:"designation"` // Professor, Associate Professor, Assistant Professor
	Email          string    `json:"email"`
	Phone          string    `json:"phone"`
	Specialization string    `json:"specialization"`
	JoiningYear    int       `json:"joiningYear"`
	Status         string    `json:"status"` // ACTIVE, ON_LEAVE, RETIRED
	CreatedBy      string    `json:"createdBy"`
	CreatedAt      time.Time `json:"createdAt"`
	ModifiedBy     string    `json:"modifiedBy"`
	ModifiedAt     time.Time `json:"modifiedAt"`
}

// AuditEntry represents a single entry in an audit trail (history for a key)
type AuditEntry struct {
	TxID      string    `json:"txId"`
	Timestamp time.Time `json:"timestamp"`
	IsDelete  bool      `json:"isDelete"`
	Value     string    `json:"value"`
}

// CertificateRequest represents a request for a certificate with multi-level approval
type CertificateRequest struct {
	RequestID       string    `json:"requestId"`
	StudentID       string    `json:"studentId"`
	CertificateType string    `json:"certificateType"`
	Reason          string    `json:"reason"`
	Status          string    `json:"status"` // REQUESTED, RECOMMENDED, APPROVED, REJECTED, ISSUED
	RequestedAt     time.Time `json:"requestedAt"`
	RecommendedBy   string    `json:"recommendedBy"`
	RecommendedAt   time.Time `json:"recommendedAt"`
	ApprovedBy      string    `json:"approvedBy"`
	ApprovedAt      time.Time `json:"approvedAt"`
	RejectedBy      string    `json:"rejectedBy"`
	RejectedAt      time.Time `json:"rejectedAt"`
	RejectionReason string    `json:"rejectionReason"`
}

// VerificationLog represents a log entry for certificate verification activity
type VerificationLog struct {
	LogID         string    `json:"logId"`
	CertificateID string    `json:"certificateId"`
	VerifierMSP   string    `json:"verifierMsp"`
	VerifierID    string    `json:"verifierId"`
	Timestamp     time.Time `json:"timestamp"`
	Purpose       string    `json:"purpose"`
}

// StudentTranscript represents a complete student transcript view
type StudentTranscript struct {
	Student      *Student          `json:"student"`
	Records      []*AcademicRecord `json:"records"`
	Certificates []*Certificate    `json:"certificates"`
}

// Constants for validation
const (
	// Valid student statuses
	StatusActive              = "ACTIVE"
	StatusGraduated           = "GRADUATED"
	StatusWithdrawn           = "WITHDRAWN"
	StatusCancelled           = "CANCELLED"
	StatusTemporaryWithdrawal = "TEMPORARY_WITHDRAWAL"

	// Valid record statuses
	RecordDraft        = "DRAFT"
	RecordSubmitted    = "SUBMITTED"
	RecordDeptApproved = "DEPT_APPROVED"
	RecordApproved     = "APPROVED"
	RecordRejected     = "REJECTED"
	StatusDraft        = "DRAFT" // Alias for consistency

	// Faculty statuses
	FacultyActive  = "ACTIVE"
	FacultyOnLeave = "ON_LEAVE"
	FacultyRetired = "RETIRED"

	// Certificate request statuses
	CertReqRequested   = "REQUESTED"
	CertReqRecommended = "RECOMMENDED"
	CertReqApproved    = "APPROVED"
	CertReqRejected    = "REJECTED"
	CertReqIssued      = "ISSUED"

	// Valid grades (10-point scale: S,A,B,C,D,P,U,R)
	GradeS = "S" // 10 points - Outstanding
	GradeA = "A" // 9 points  - Excellent
	GradeB = "B" // 8 points  - Very Good
	GradeC = "C" // 7 points  - Good
	GradeD = "D" // 6 points  - Satisfactory
	GradeP = "P" // 5 points  - Pass
	GradeU = "U" // 0 points  - Unsatisfactory/Fail
	GradeR = "R" // 0 points  - Repeat (Attendance shortage)

	// Credit limits
	MinCredits = 0.5
	MaxCredits = 6.0

	// Semester limits
	MinSemesterCredits = 16.0
	MaxSemesterCredits = 30.0

	// Organization MSP IDs
	NITWarangalMSP = "NITWarangalMSP"
	DepartmentsMSP = "DepartmentsMSP"
	VerifiersMSP   = "VerifiersMSP"

	// Certificate types
	CertDegree       = "DEGREE"
	CertTranscript   = "TRANSCRIPT"
	CertProvisional  = "PROVISIONAL"
	CertBonafide     = "BONAFIDE"
	CertMigration    = "MIGRATION"
	CertCharacter    = "CHARACTER"
	CertStudyConduct = "STUDY_CONDUCT"

	// Composite key prefixes
	StudentAllKey     = "student~all"
	StudentDeptKey    = "student~dept"
	StudentYearKey    = "student~year"
	StudentStatusKey  = "student~status"
	StudentRecordKey  = "student~record"
	RecordSemesterKey = "record~semester"
	RecordStatusKey   = "record~status"
	RecordDeptKey     = "record~department"
	CertStudentKey    = "cert~student"
	DepartmentAllKey  = "department~all"
	CourseOfferingKey = "course~offering"
	CourseDeptKey     = "course~dept"

	// Faculty composite key prefixes
	FacultyAllKey  = "faculty~all"
	FacultyDeptKey = "faculty~dept"

	// Record "all" key for GetAllAcademicRecords
	RecordAllKey = "record~all"

	// Certificate request composite key prefixes
	CertReqStudentKey = "certreq~student"
	CertReqStatusKey  = "certreq~status"

	// Verification log composite key prefix
	VerificationCertKey = "verification~cert"
)

// Validation helper functions

// validateEmail checks if email is valid NIT Warangal student email
func validateEmail(email string) error {
	if !strings.HasSuffix(email, "@student.nitw.ac.in") {
		return fmt.Errorf("email must be @student.nitw.ac.in domain")
	}
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@student\.nitw\.ac\.in$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// validateGrade checks if grade is valid
func validateGrade(grade string) error {
	validGrades := []string{GradeS, GradeA, GradeB, GradeC, GradeD, GradeP, GradeU, GradeR}
	for _, vg := range validGrades {
		if grade == vg {
			return nil
		}
	}
	return fmt.Errorf("invalid grade '%s'. Valid grades: S, A, B, C, D, P, U, R", grade)
}

// validateCredits checks if credit value is valid
func validateCredits(credits float64) error {
	if credits < MinCredits || credits > MaxCredits {
		return fmt.Errorf("credits must be between %.1f and %.1f", MinCredits, MaxCredits)
	}
	return nil
}

// validateSemester checks if semester number is valid (1-8 for B.Tech)
func validateSemester(semester int) error {
	if semester < 1 || semester > 8 {
		return fmt.Errorf("semester must be between 1 and 8")
	}
	return nil
}

// validateStatus checks if status is valid
func validateStatus(status string) error {
	validStatuses := []string{StatusActive, StatusGraduated, StatusWithdrawn, StatusCancelled, StatusTemporaryWithdrawal}
	for _, vs := range validStatuses {
		if status == vs {
			return nil
		}
	}
	return fmt.Errorf("invalid status '%s'", status)
}

// validateCertificateType checks if certificate type is valid
func validateCertificateType(certType string) error {
	validTypes := []string{CertDegree, CertTranscript, CertProvisional, CertBonafide, CertMigration, CertCharacter, CertStudyConduct}
	for _, vt := range validTypes {
		if certType == vt {
			return nil
		}
	}
	return fmt.Errorf("invalid certificate type '%s'", certType)
}

// validateFacultyStatus checks if the faculty status is valid
func validateFacultyStatus(status string) error {
	validStatuses := []string{FacultyActive, FacultyOnLeave, FacultyRetired}
	for _, vs := range validStatuses {
		if status == vs {
			return nil
		}
	}
	return fmt.Errorf("invalid faculty status '%s'. Valid statuses: ACTIVE, ON_LEAVE, RETIRED", status)
}

// validateRecordStatus checks if the academic record status is valid (including new statuses)
func validateRecordStatus(status string) error {
	validStatuses := []string{RecordDraft, RecordSubmitted, RecordDeptApproved, RecordApproved, RecordRejected}
	for _, vs := range validStatuses {
		if status == vs {
			return nil
		}
	}
	return fmt.Errorf("invalid record status '%s'", status)
}

// validateCertReqStatus checks if the certificate request status is valid
func validateCertReqStatus(status string) error {
	validStatuses := []string{CertReqRequested, CertReqRecommended, CertReqApproved, CertReqRejected, CertReqIssued}
	for _, vs := range validStatuses {
		if status == vs {
			return nil
		}
	}
	return fmt.Errorf("invalid certificate request status '%s'", status)
}

// facultyExists checks if a faculty member exists
func (s *SmartContract) facultyExists(ctx contractapi.TransactionContextInterface, facultyID string) (bool, error) {
	facultyJSON, err := ctx.GetStub().GetState(facultyID)
	if err != nil {
		return false, fmt.Errorf("failed to read faculty: %v", err)
	}
	return facultyJSON != nil, nil
}

// checkClientAttribute verifies if the client has a specific attribute with the expected value
func checkClientAttribute(ctx contractapi.TransactionContextInterface, attributeName, expectedValue string) error {
	val, found, err := ctx.GetClientIdentity().GetAttributeValue(attributeName)
	if err != nil {
		return fmt.Errorf("failed to get client attribute '%s': %w", attributeName, err)
	}
	if !found {
		return fmt.Errorf("client attribute '%s' not found", attributeName)
	}
	if val != expectedValue {
		return fmt.Errorf("unauthorized: client attribute '%s' is '%s', but expected '%s'", attributeName, val, expectedValue)
	}
	return nil
}

// Access control helper functions

// checkMSPAccess verifies if caller is from allowed organization
func checkMSPAccess(ctx contractapi.TransactionContextInterface, allowedMSPs ...string) error {
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}

	for _, msp := range allowedMSPs {
		if clientMSPID == msp {
			return nil
		}
	}
	return fmt.Errorf("unauthorized: only %v can perform this operation", allowedMSPs)
}

// checkDepartmentAccess verifies if caller can access department-specific data
func checkDepartmentAccess(ctx contractapi.TransactionContextInterface, department string) error {
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}

	// NITWarangalMSP has access to all departments
	if clientMSPID == NITWarangalMSP {
		return nil
	}

	// DepartmentsMSP can only access their own department via an attribute
	if clientMSPID == DepartmentsMSP {
		err := checkClientAttribute(ctx, "department", department)
		if err != nil {
			return fmt.Errorf("department access check failed: %w", err)
		}
		return nil
	}

	return fmt.Errorf("unauthorized")
}

// InitLedger initializes the ledger with sample data
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	fmt.Println("Initializing NIT Warangal Academic Records Blockchain - Production Version")

	// Emit initialization event
	err := ctx.GetStub().SetEvent("LedgerInitialized", []byte(time.Now().String()))
	if err != nil {
		return fmt.Errorf("failed to set event: %v", err)
	}

	return nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating academic records chaincode: %v\n", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting academic records chaincode: %v\n", err)
	}
}
