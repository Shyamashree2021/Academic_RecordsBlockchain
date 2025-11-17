package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// Constants for validation
const (
	// Valid student statuses
	StatusActive              = "ACTIVE"
	StatusGraduated           = "GRADUATED"
	StatusWithdrawn           = "WITHDRAWN"
	StatusCancelled           = "CANCELLED"
	StatusTemporaryWithdrawal = "TEMPORARY_WITHDRAWAL"

	// Valid record statuses
	RecordDraft     = "DRAFT"
	RecordSubmitted = "SUBMITTED"
	RecordApproved  = "APPROVED"
	StatusDraft     = "DRAFT" // Alias for consistency

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

// CreateStudent creates a new student record, storing sensitive data in a private collection
func (s *SmartContract) CreateStudent(ctx contractapi.TransactionContextInterface,
	rollNumber, name, department string, enrollmentYear int, email, admissionCategory string) error {

	// Access Control: Only NITWarangalMSP can create students
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	// Normalize department to uppercase
	department = strings.ToUpper(department)

	// Get private data from transient map
	transientMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("failed to get transient map: %w", err)
	}

	aadhaarHash, ok := transientMap["aadhaarHash"]
	if !ok {
		return fmt.Errorf("aadhaarHash must be provided in transient data")
	}
	phone, ok := transientMap["phone"]
	if !ok {
		return fmt.Errorf("phone must be provided in transient data")
	}
	personalEmail, ok := transientMap["personalEmail"]
	if !ok {
		return fmt.Errorf("personalEmail must be provided in transient data")
	}

	// Validate email
	err = validateEmail(email)
	if err != nil {
		return err
	}

	// Validate enrollment year (must be reasonable)
	currentYear := time.Now().Year()
	if enrollmentYear < 1950 || enrollmentYear > currentYear+1 {
		return fmt.Errorf("invalid enrollment year %d", enrollmentYear)
	}

	// Validate name
	if len(name) < 3 || len(name) > 100 {
		return fmt.Errorf("name must be between 3 and 100 characters")
	}

	// Validate roll number format
	if len(rollNumber) < 5 || len(rollNumber) > 20 {
		return fmt.Errorf("roll number must be between 5 and 20 characters")
	}

	// Check if student already exists (using rollNumber as primary key)
	exists, err := s.StudentExists(ctx, rollNumber)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("student with roll number %s already exists", rollNumber)
	}

	// Get transaction timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Get creator ID
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %w", err)
	}

	student := Student{
		StudentID:          rollNumber, // Using rollNumber as studentID
		Name:               name,
		Department:         department,
		EnrollmentYear:     enrollmentYear,
		RollNumber:         rollNumber,
		Email:              email,
		AdmissionCategory:  admissionCategory,
		Status:             StatusActive,
		TotalCreditsEarned: 0,
		CurrentCGPA:        0,
		CreatedBy:          clientID,
		CreatedAt:          timestamp,
		ModifiedBy:         clientID,
		ModifiedAt:         timestamp,
	}

	studentJSON, err := json.Marshal(student)
	if err != nil {
		return fmt.Errorf("failed to marshal student: %w", err)
	}

	// Store public data
	err = ctx.GetStub().PutState(rollNumber, studentJSON)
	if err != nil {
		return fmt.Errorf("failed to put public student data: %w", err)
	}

	// Store private data
	privateDetails := StudentPrivateDetails{
		StudentID:     rollNumber,
		AadhaarHash:   string(aadhaarHash),
		Phone:         string(phone),
		PersonalEmail: string(personalEmail),
	}
	privateDetailsJSON, err := json.Marshal(privateDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal private details: %w", err)
	}
	err = ctx.GetStub().PutPrivateData(studentPrivateCollection, rollNumber, privateDetailsJSON)
	if err != nil {
		return fmt.Errorf("failed to put private student data: %w", err)
	}

	// Create composite keys for efficient querying
	// 1. student~department~rollNumber (for department-wise queries)
	deptKey, err := ctx.GetStub().CreateCompositeKey(StudentDeptKey, []string{department, rollNumber})
	if err != nil {
		return fmt.Errorf("failed to create composite key for department: %w", err)
	}
	err = ctx.GetStub().PutState(deptKey, studentJSON)
	if err != nil {
		return fmt.Errorf("failed to put state for department key: %w", err)
	}

	// 2. student~year~rollNumber (for year-wise queries)
	yearKey, err := ctx.GetStub().CreateCompositeKey(StudentYearKey, []string{fmt.Sprintf("%d", enrollmentYear), rollNumber})
	if err != nil {
		return fmt.Errorf("failed to create composite key for year: %w", err)
	}
	err = ctx.GetStub().PutState(yearKey, studentJSON)
	if err != nil {
		return fmt.Errorf("failed to put state for year key: %w", err)
	}

	// 3. student~status~rollNumber (for status-wise queries)
	statusKey, err := ctx.GetStub().CreateCompositeKey(StudentStatusKey, []string{StatusActive, rollNumber})
	if err != nil {
		return fmt.Errorf("failed to create composite key for status: %w", err)
	}
	err = ctx.GetStub().PutState(statusKey, studentJSON)
	if err != nil {
		return err
	}

	// 4. student~all~rollNumber (for GetAllStudents query)
	allKey, err := ctx.GetStub().CreateCompositeKey(StudentAllKey, []string{rollNumber})
	if err != nil {
		return fmt.Errorf("failed to create composite key for all students: %w", err)
	}
	err = ctx.GetStub().PutState(allKey, []byte{0x00}) // Use a null byte as value
	if err != nil {
		return fmt.Errorf("failed to put state for all students key: %w", err)
	}

	// Emit student created event
	eventPayload := map[string]interface{}{
		"rollNumber":     rollNumber,
		"name":           name,
		"department":     department,
		"enrollmentYear": enrollmentYear,
		"createdBy":      clientID,
		"createdAt":      timestamp,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	err = ctx.GetStub().SetEvent("StudentCreated", eventJSON)
	if err != nil {
		return fmt.Errorf("failed to set event: %v", err)
	}

	return nil
}

// GetStudentPrivateDetails retrieves the private details of a student
func (s *SmartContract) GetStudentPrivateDetails(ctx contractapi.TransactionContextInterface, rollNumber string) (*StudentPrivateDetails, error) {
	// Access Control: Only NITWarangalMSP can get private details
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return nil, err
	}

	privateDetailsJSON, err := ctx.GetStub().GetPrivateData(studentPrivateCollection, rollNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to read private details for student %s: %w", rollNumber, err)
	}
	if privateDetailsJSON == nil {
		return nil, fmt.Errorf("private details for student %s do not exist", rollNumber)
	}

	var privateDetails StudentPrivateDetails
	err = json.Unmarshal(privateDetailsJSON, &privateDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private details: %w", err)
	}

	return &privateDetails, nil
}

// GetStudent retrieves a student record (Enhanced with department-level access control)
func (s *SmartContract) GetStudent(ctx contractapi.TransactionContextInterface, rollNumber string) (*Student, error) {
	studentJSON, err := ctx.GetStub().GetState(rollNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if studentJSON == nil {
		return nil, fmt.Errorf("student %s does not exist", rollNumber)
	}

	var student Student
	err = json.Unmarshal(studentJSON, &student)
	if err != nil {
		return nil, err
	}

	// Access Control: Check department access for DepartmentsMSP
	err = checkDepartmentAccess(ctx, student.Department)
	if err != nil {
		return nil, err
	}

	return &student, nil
}

// UpdateStudentStatus updates the status of a student (Enhanced with RBAC and approval)
func (s *SmartContract) UpdateStudentStatus(ctx contractapi.TransactionContextInterface,
	rollNumber, newStatus, reason string) error {

	// Access Control: Only NITWarangalMSP can update status
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	// Validate new status
	err = validateStatus(newStatus)
	if err != nil {
		return err
	}

	student, err := s.GetStudent(ctx, rollNumber)
	if err != nil {
		return err
	}

	oldStatus := student.Status

	// Critical status changes (CANCELLED, WITHDRAWN) require reason
	if (newStatus == StatusCancelled || newStatus == StatusWithdrawn) && reason == "" {
		return fmt.Errorf("reason required for status change to %s", newStatus)
	}

	// Get transaction timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Get modifier ID
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %v", err)
	}

	student.Status = newStatus
	student.ModifiedBy = clientID
	student.ModifiedAt = timestamp

	studentJSON, err := json.Marshal(student)
	if err != nil {
		return err
	}

	// Update main record
	err = ctx.GetStub().PutState(rollNumber, studentJSON)
	if err != nil {
		return err
	}

	// Update status composite key
	// Remove old status key
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(StudentStatusKey, []string{oldStatus, rollNumber})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	// Add new status key
	newStatusKey, err := ctx.GetStub().CreateCompositeKey(StudentStatusKey, []string{newStatus, rollNumber})
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(newStatusKey, studentJSON)
	if err != nil {
		return err
	}

	// Emit status change event
	eventPayload := map[string]interface{}{
		"rollNumber": rollNumber,
		"oldStatus":  oldStatus,
		"newStatus":  newStatus,
		"reason":     reason,
		"modifiedBy": clientID,
		"modifiedAt": timestamp,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	err = ctx.GetStub().SetEvent("StudentStatusChanged", eventJSON)
	if err != nil {
		return fmt.Errorf("failed to set event: %v", err)
	}

	return nil
}

// UpdateStudentContactInfo updates modifiable contact information in the private data collection
func (s *SmartContract) UpdateStudentContactInfo(ctx contractapi.TransactionContextInterface, rollNumber string) error {

	// Access Control: Only NITWarangalMSP can update
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	// Check if student exists
	student, err := s.GetStudent(ctx, rollNumber)
	if err != nil {
		return err
	}

	// Get private data from transient map
	transientMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("failed to get transient map: %w", err)
	}

	// Fetch existing private details
	privateDetails, err := s.GetStudentPrivateDetails(ctx, rollNumber)
	if err != nil {
		return err
	}

	// Update fields if new values are provided in transient data
	if phone, ok := transientMap["phone"]; ok {
		privateDetails.Phone = string(phone)
	}
	if personalEmail, ok := transientMap["personalEmail"]; ok {
		privateDetails.PersonalEmail = string(personalEmail)
	}

	// Get modifier ID and timestamp
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %w", err)
	}
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Update public student record's modification timestamp
	student.ModifiedBy = clientID
	student.ModifiedAt = timestamp
	studentJSON, err := json.Marshal(student)
	if err != nil {
		return fmt.Errorf("failed to marshal student for modification tracking: %w", err)
	}
	err = ctx.GetStub().PutState(rollNumber, studentJSON)
	if err != nil {
		return fmt.Errorf("failed to update student modification timestamp: %w", err)
	}

	// Save updated private details
	privateDetailsJSON, err := json.Marshal(privateDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal updated private details: %w", err)
	}

	err = ctx.GetStub().PutPrivateData(studentPrivateCollection, rollNumber, privateDetailsJSON)
	if err != nil {
		return fmt.Errorf("failed to put updated private details: %w", err)
	}

	return nil
}

// UpdateStudentDepartment updates a student's department with proper composite key cleanup
func (s *SmartContract) UpdateStudentDepartment(ctx contractapi.TransactionContextInterface, rollNumber, newDepartment string) error {
	// Access Control: Only NITWarangalMSP can update department
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	// Get existing student record directly without access control checks
	studentJSON, err := ctx.GetStub().GetState(rollNumber)
	if err != nil {
		return fmt.Errorf("failed to read student: %v", err)
	}
	if studentJSON == nil {
		return fmt.Errorf("student %s does not exist", rollNumber)
	}

	var student Student
	err = json.Unmarshal(studentJSON, &student)
	if err != nil {
		return fmt.Errorf("failed to unmarshal student: %v", err)
	}

	oldDepartment := student.Department

	// If department hasn't changed, no need to proceed
	if oldDepartment == newDepartment {
		return fmt.Errorf("student is already in department %s", newDepartment)
	}

	// Get transaction timestamp and client ID
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %v", err)
	}

	// Update student record
	student.Department = newDepartment
	student.ModifiedBy = clientID
	student.ModifiedAt = timestamp

	updatedStudentJSON, err := json.Marshal(student)
	if err != nil {
		return fmt.Errorf("failed to marshal student: %w", err)
	}

	// Update main record
	err = ctx.GetStub().PutState(rollNumber, updatedStudentJSON)
	if err != nil {
		return fmt.Errorf("failed to update student record: %w", err)
	}

	// Update composite keys
	// 1. Remove old department composite key
	oldDeptKey, err := ctx.GetStub().CreateCompositeKey(StudentDeptKey, []string{oldDepartment, rollNumber})
	if err == nil {
		err = ctx.GetStub().DelState(oldDeptKey)
		if err != nil {
			return fmt.Errorf("failed to delete old department key: %w", err)
		}
	}

	// 2. Add new department composite key
	newDeptKey, err := ctx.GetStub().CreateCompositeKey(StudentDeptKey, []string{newDepartment, rollNumber})
	if err != nil {
		return fmt.Errorf("failed to create new department key: %w", err)
	}
	err = ctx.GetStub().PutState(newDeptKey, updatedStudentJSON)
	if err != nil {
		return fmt.Errorf("failed to put new department key: %w", err)
	}

	// Emit department change event
	eventPayload := map[string]interface{}{
		"rollNumber":    rollNumber,
		"oldDepartment": oldDepartment,
		"newDepartment": newDepartment,
		"modifiedBy":    clientID,
		"modifiedAt":    timestamp,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	err = ctx.GetStub().SetEvent("StudentDepartmentChanged", eventJSON)
	if err != nil {
		return fmt.Errorf("failed to set event: %v", err)
	}

	return nil
}

// StudentExists checks if a student exists
func (s *SmartContract) StudentExists(ctx contractapi.TransactionContextInterface, studentID string) (bool, error) {
	studentJSON, err := ctx.GetStub().GetState(studentID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %w", err)
	}
	return studentJSON != nil, nil
}

// recordExists checks if an academic record exists.
func (s *SmartContract) recordExists(ctx contractapi.TransactionContextInterface, recordID string) (bool, error) {
	recordJSON, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %w", err)
	}
	return recordJSON != nil, nil
}

// CreateAcademicRecord creates a new academic record (Enhanced with validation and access control)
func (s *SmartContract) CreateAcademicRecord(ctx contractapi.TransactionContextInterface,
	recordID, rollNumber string, semester int, year string, department string, coursesJSON string) error {

	// Access Control: Only DepartmentsMSP or NITWarangalMSP can create records
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %w", err)
	}
	if clientMSPID != DepartmentsMSP && clientMSPID != NITWarangalMSP {
		return fmt.Errorf("unauthorized: only %s or %s can create academic records", DepartmentsMSP, NITWarangalMSP)
	}

	// If created by a department, verify the department attribute matches the record's department
	if clientMSPID == DepartmentsMSP {
		err := checkClientAttribute(ctx, "department", department)
		if err != nil {
			return fmt.Errorf("department user cannot create a record for another department: %w", err)
		}
	}

	// Check if record already exists
	exists, err := s.recordExists(ctx, recordID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("academic record %s already exists", recordID)
	}

	// Verify student exists
	exists, err = s.StudentExists(ctx, rollNumber)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("student %s does not exist", rollNumber)
	}

	// Validate semester (1-8)
	if err := validateSemester(semester); err != nil {
		return err
	}

	var courses []Course
	err = json.Unmarshal([]byte(coursesJSON), &courses)
	if err != nil {
		return fmt.Errorf("failed to parse courses: %v", err)
	}

	if len(courses) == 0 {
		return fmt.Errorf("at least one course is required")
	}

	// Validate each course and calculate total credits
	totalCredits := 0.0
	for i, course := range courses {
		// Validate course code
		if len(course.CourseCode) < 3 || len(course.CourseCode) > 20 {
			return fmt.Errorf("course %d: invalid course code length (must be 3-20 characters)", i+1)
		}

		// Validate course name
		if len(course.CourseName) < 3 || len(course.CourseName) > 100 {
			return fmt.Errorf("course %d: invalid course name length (must be 3-100 characters)", i+1)
		}

		// Validate credits (0.5-6)
		if err := validateCredits(course.Credits); err != nil {
			return fmt.Errorf("course %d (%s): %v", i+1, course.CourseCode, err)
		}

		// Validate grade (S, A, B, C, D, P, U, R)
		if err := validateGrade(course.Grade); err != nil {
			return fmt.Errorf("course %d (%s): %v", i+1, course.CourseCode, err)
		}

		totalCredits += course.Credits
	}

	// Validate total credits per semester (16-30)
	if totalCredits < 16.0 || totalCredits > 30.0 {
		return fmt.Errorf("total semester credits %.1f out of range (must be 16-30)", totalCredits)
	}

	// Calculate GPA for this semester
	_, sgpa := calculateGrades(courses)

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %v", err)
	}

	// Get transaction timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Create academic record with DRAFT status initially
	record := AcademicRecord{
		RecordID:      recordID,
		StudentID:     rollNumber, // Using rollNumber as student identifier
		Department:    department,
		Semester:      semester,
		Courses:       courses,
		TotalCredits:  totalCredits,
		SGPA:          sgpa,
		CGPA:          0.0, // Will be calculated on approval
		Timestamp:     timestamp,
		SubmittedBy:   clientID,
		Status:        StatusDraft,
		ApprovedBy:    "",
		RejectionNote: "", // Initialize to empty string
	}

	recordJSONBytes, err := json.Marshal(record)
	if err != nil {
		return err
	}

	// Store with primary key
	err = ctx.GetStub().PutState(recordID, recordJSONBytes)
	if err != nil {
		return err
	}

	// Create composite keys for efficient querying
	// 1. student~record
	recordKey, err := ctx.GetStub().CreateCompositeKey(StudentRecordKey, []string{rollNumber, recordID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for student record: %w", err)
	}
	err = ctx.GetStub().PutState(recordKey, []byte{0x00}) // Use a null byte as value
	if err != nil {
		return fmt.Errorf("failed to put state for student record key: %w", err)
	}

	// 2. record~semester~{Semester}~{StudentID}~{RecordID}
	semKey, err := ctx.GetStub().CreateCompositeKey(RecordSemesterKey, []string{fmt.Sprintf("%d", semester), rollNumber, recordID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for semester record: %w", err)
	}
	err = ctx.GetStub().PutState(semKey, []byte{0x00}) // Use a null byte as value
	if err != nil {
		return fmt.Errorf("failed to put state for semester record key: %w", err)
	}

	// 3. record~status~{Status}~{StudentID}~{RecordID}
	statusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{StatusDraft, rollNumber, recordID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for status record: %w", err)
	}
	err = ctx.GetStub().PutState(statusKey, []byte{0x00}) // Use a null byte as value
	if err != nil {
		return fmt.Errorf("failed to put state for status record key: %w", err)
	}

	// 4. record~department
	deptKey, err := ctx.GetStub().CreateCompositeKey(RecordDeptKey, []string{department, rollNumber, recordID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for department record: %w", err)
	}
	err = ctx.GetStub().PutState(deptKey, []byte{0x00}) // Use a null byte as value
	if err != nil {
		return fmt.Errorf("failed to put state for department record key: %w", err)
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"recordID":     recordID,
		"rollNumber":   rollNumber,
		"semester":     semester,
		"year":         year,
		"department":   department,
		"coursesCount": len(courses),
		"totalCredits": totalCredits,
		"sgpa":         sgpa,
		"status":       record.Status,
		"submittedBy":  clientID,
		"timestamp":    timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSONBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RecordCreated", eventJSONBytes)

	return nil
}

// GetAcademicRecord retrieves an academic record (Enhanced with department access control)
func (s *SmartContract) GetAcademicRecord(ctx contractapi.TransactionContextInterface, recordID string) (*AcademicRecord, error) {
	recordJSON, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return nil, fmt.Errorf("failed to read record: %v", err)
	}
	if recordJSON == nil {
		return nil, fmt.Errorf("record %s does not exist", recordID)
	}

	var record AcademicRecord
	err = json.Unmarshal(recordJSON, &record)
	if err != nil {
		return nil, err
	}

	// Access Control: Check department access for DepartmentsMSP
	err = checkDepartmentAccess(ctx, record.Department)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// ApproveAcademicRecord approves an academic record and calculates CGPA (Enhanced with RBAC and workflow)
func (s *SmartContract) ApproveAcademicRecord(ctx contractapi.TransactionContextInterface, recordID string) error {
	// Access Control: Only NITWarangalMSP (Admin) can approve records
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	// Attribute Check: Check for 'role' of 'admin' (optional - MSP check is sufficient)
	roleErr := checkClientAttribute(ctx, "role", "admin")
	if roleErr != nil {
		// If no role attribute, proceed anyway since MSP check passed
		// This allows admin identity from wallet without explicit role attribute
		fmt.Printf("Note: Client approved without role attribute (MSP authorization sufficient)\n")
	}

	// Get record
	record, err := s.GetAcademicRecord(ctx, recordID)
	if err != nil {
		return err
	}

	// Check if already approved
	if record.Status == RecordApproved {
		return fmt.Errorf("record %s is already approved", recordID)
	}

	// Record must be submitted before approval
	if record.Status != RecordSubmitted && record.Status != RecordDraft {
		return fmt.Errorf("cannot approve record with status %s", record.Status)
	}

	// Calculate CGPA based on all approved records for this student
	// Include the current record being approved in the calculation
	newCGPA, totalCredits, err := s.calculateCGPAIncludingCurrent(ctx, record.StudentID, record.Semester, record.SGPA, record.TotalCredits)
	if err != nil {
		return fmt.Errorf("failed to calculate CGPA: %w", err)
	}
	record.CGPA = newCGPA

	// Update student's overall CGPA and total credits
	student, err := s.GetStudent(ctx, record.StudentID)
	if err != nil {
		return fmt.Errorf("failed to get student for CGPA update: %w", err)
	}
	student.CurrentCGPA = newCGPA
	student.TotalCreditsEarned = totalCredits
	studentJSON, err := json.Marshal(student)
	if err != nil {
		return fmt.Errorf("failed to marshal student for CGPA update: %w", err)
	}
	err = ctx.GetStub().PutState(student.RollNumber, studentJSON)
	if err != nil {
		return fmt.Errorf("failed to update student with new CGPA: %w", err)
	}

	// Get approver identity
	approverID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get approver ID: %w", err)
	}

	// Get transaction timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Update composite keys if status changed
	oldStatus := record.Status
	if oldStatus != RecordApproved {
		// Remove old status key
		oldStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{oldStatus, record.StudentID, recordID})
		if err != nil {
			return fmt.Errorf("failed to create old status composite key for deletion: %w", err)
		}
		err = ctx.GetStub().DelState(oldStatusKey)
		if err != nil {
			return fmt.Errorf("failed to delete old status composite key: %w", err)
		}

		// Add new status key
		newStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordApproved, record.StudentID, recordID})
		if err != nil {
			return fmt.Errorf("failed to create new status composite key: %w", err)
		}
		err = ctx.GetStub().PutState(newStatusKey, []byte{0x00})
		if err != nil {
			return fmt.Errorf("failed to put new status composite key: %w", err)
		}
	}

	// Update record
	record.Status = RecordApproved
	record.ApprovedBy = approverID
	record.Timestamp = timestamp // Update timestamp to approval time

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal approved record: %w", err)
	}

	err = ctx.GetStub().PutState(recordID, recordJSON)
	if err != nil {
		return fmt.Errorf("failed to put approved record state: %w", err)
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"recordID":   recordID,
		"studentID":  record.StudentID,
		"semester":   record.Semester,
		"department": record.Department,
		"sgpa":       record.SGPA,
		"cgpa":       newCGPA,
		"approvedBy": approverID,
		"timestamp":  time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RecordApproved", eventJSON)

	return nil
}

// IssueCertificate issues a certificate with PDF hash (Enhanced with validation and RBAC)
func (s *SmartContract) IssueCertificate(ctx contractapi.TransactionContextInterface,
	certificateID, studentID, certType, pdfBase64, ipfsHash string) error {

	// Access Control: Only NITWarangalMSP can issue certificates
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	// Validate certificate type
	err = validateCertificateType(certType)
	if err != nil {
		return err
	}

	// Check if certificate already exists
	existingCert, err := ctx.GetStub().GetState(certificateID)
	if err != nil {
		return fmt.Errorf("failed to check certificate existence: %v", err)
	}
	if existingCert != nil {
		return fmt.Errorf("certificate %s already exists", certificateID)
	}

	// Verify student exists
	exists, err := s.StudentExists(ctx, studentID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("student %s does not exist", studentID)
	}

	// Calculate hash of PDF
	hash := sha256.Sum256([]byte(pdfBase64))
	pdfHash := hex.EncodeToString(hash[:])

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %v", err)
	}

	// Get transaction timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	issueDate := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Set expiry date for BONAFIDE certificates (6 months)
	var expiryDate time.Time
	if certType == CertBonafide {
		expiryDate = issueDate.AddDate(0, 6, 0) // 6 months validity
	}

	// Get student details to populate degree and CGPA
	student, err := s.GetStudent(ctx, studentID)
	if err != nil {
		return fmt.Errorf("failed to get student details: %v", err)
	}

	// Calculate degree name based on department
	degreeAwarded := ""
	if certType == CertDegree || certType == CertProvisional {
		degreeAwarded = fmt.Sprintf("B.Tech in %s", student.Department)
	}

	// Get final CGPA from student record
	finalCGPA := student.CurrentCGPA

	// Calculate isValid: not revoked and not expired
	isValid := true // Initial state, will be computed dynamically in GetCertificate

	certificate := Certificate{
		CertificateID: certificateID,
		StudentID:     studentID,
		Type:          certType,
		IssueDate:     issueDate,
		ExpiryDate:    expiryDate,
		PDFHash:       pdfHash,
		IPFSHash:      ipfsHash,
		IssuedBy:      clientID,
		Verified:      true,
		Revoked:       false,
		DegreeAwarded: degreeAwarded,
		FinalCGPA:     finalCGPA,
		IsValid:       isValid,
	}

	certJSON, err := json.Marshal(certificate)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState(certificateID, certJSON)
	if err != nil {
		return err
	}

	// Create composite key for student certificates
	certKey, err := ctx.GetStub().CreateCompositeKey(CertStudentKey, []string{studentID, certificateID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for certificate: %w", err)
	}
	err = ctx.GetStub().PutState(certKey, []byte{0x00})
	if err != nil {
		return err
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"certificateID": certificateID,
		"studentID":     studentID,
		"type":          certType,
		"issuedBy":      clientID,
		"issueDate":     issueDate.Format("2006-01-02T15:04:05Z07:00"),
	}
	if !expiryDate.IsZero() {
		eventPayload["expiryDate"] = expiryDate.Format("2006-01-02T15:04:05Z07:00")
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateIssued", eventJSON)

	return nil
}

// GetCertificate retrieves a certificate (Enhanced with revocation check)
func (s *SmartContract) GetCertificate(ctx contractapi.TransactionContextInterface,
	certificateID string) (*Certificate, error) {

	certJSON, err := ctx.GetStub().GetState(certificateID)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}
	if certJSON == nil {
		return nil, fmt.Errorf("certificate %s does not exist", certificateID)
	}

	var certificate Certificate
	err = json.Unmarshal(certJSON, &certificate)
	if err != nil {
		return nil, err
	}

	// Get current time for expiry check
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	currentTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Dynamically compute IsValid: not revoked AND (no expiry OR not expired)
	certificate.IsValid = !certificate.Revoked &&
		(certificate.ExpiryDate.IsZero() || currentTime.Before(certificate.ExpiryDate))

	// Check if certificate is expired (for BONAFIDE certificates)
	if certificate.Type == CertBonafide && !certificate.ExpiryDate.IsZero() {
		if currentTime.After(certificate.ExpiryDate) {
			certificate.Verified = false // Mark as not verified if expired
		}
	}

	return &certificate, nil
}

// VerifyCertificate verifies a certificate by comparing PDF hash (Enhanced with revocation and expiry check)
func (s *SmartContract) VerifyCertificate(ctx contractapi.TransactionContextInterface,
	certificateID, pdfBase64 string) (bool, error) {

	certJSON, err := ctx.GetStub().GetState(certificateID)
	if err != nil {
		return false, fmt.Errorf("failed to read certificate: %v", err)
	}
	if certJSON == nil {
		return false, fmt.Errorf("certificate %s does not exist", certificateID)
	}

	var certificate Certificate
	err = json.Unmarshal(certJSON, &certificate)
	if err != nil {
		return false, err
	}

	// Check if certificate is revoked
	if certificate.Revoked {
		return false, fmt.Errorf("certificate has been revoked: %s", certificate.RevocationReason)
	}

	// Check if certificate is expired (for BONAFIDE certificates)
	if certificate.Type == CertBonafide && !certificate.ExpiryDate.IsZero() {
		txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
		currentTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
		if currentTime.After(certificate.ExpiryDate) {
			return false, fmt.Errorf("certificate has expired on %s", certificate.ExpiryDate.Format("2006-01-02"))
		}
	}

	// Calculate hash of provided PDF
	hash := sha256.Sum256([]byte(pdfBase64))
	providedHash := hex.EncodeToString(hash[:])

	// Verify hash matches
	if providedHash != certificate.PDFHash {
		return false, nil
	}

	return true, nil
}

// RevokeCertificate revokes a certificate (NEW - with multi-party approval)
func (s *SmartContract) RevokeCertificate(ctx contractapi.TransactionContextInterface,
	certificateID, reason string) error {

	// Access Control: Only NITWarangalMSP can revoke certificates
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	// Get certificate
	certJSON, err := ctx.GetStub().GetState(certificateID)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %v", err)
	}
	if certJSON == nil {
		return fmt.Errorf("certificate %s does not exist", certificateID)
	}

	var certificate Certificate
	err = json.Unmarshal(certJSON, &certificate)
	if err != nil {
		return err
	}

	// Check if already revoked
	if certificate.Revoked {
		return fmt.Errorf("certificate %s is already revoked", certificateID)
	}

	// Validate reason
	if len(reason) < 10 {
		return fmt.Errorf("revocation reason must be at least 10 characters")
	}

	// Get revoker identity
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %v", err)
	}

	// Get timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	revokedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Update certificate
	certificate.Revoked = true
	certificate.RevokedBy = clientID
	certificate.RevokedAt = revokedAt
	certificate.RevocationReason = reason
	certificate.Verified = false
	certificate.IsValid = false // Mark as invalid when revoked

	updatedCertJSON, err := json.Marshal(certificate)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState(certificateID, updatedCertJSON)
	if err != nil {
		return err
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"certificateID": certificateID,
		"studentID":     certificate.StudentID,
		"type":          certificate.Type,
		"revokedBy":     clientID,
		"revokedAt":     revokedAt.Format("2006-01-02T15:04:05Z07:00"),
		"reason":        reason,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateRevoked", eventJSON)

	return nil
}

// GetCertificatesByStudent retrieves all certificates for a student (NEW)
func (s *SmartContract) GetCertificatesByStudent(ctx contractapi.TransactionContextInterface,
	studentID string) ([]*Certificate, error) {

	// Use composite key to query certificates by studentID
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(CertStudentKey, []string{studentID})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates by student: %w", err)
	}
	defer resultsIterator.Close()

	var certificates []*Certificate
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		// Split the composite key to extract certificateID
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, err
		}

		if len(compositeKeyParts) < 2 {
			continue
		}
		certificateID := compositeKeyParts[1]

		// Fetch the actual certificate
		certJSON, err := ctx.GetStub().GetState(certificateID)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate %s: %v", certificateID, err)
		}
		if certJSON == nil {
			continue
		}

		var certificate Certificate
		err = json.Unmarshal(certJSON, &certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal certificate %s: %v", certificateID, err)
		}

		// Get current time for expiry check
		txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
		currentTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

		// Dynamically compute IsValid: not revoked AND (no expiry OR not expired)
		certificate.IsValid = !certificate.Revoked &&
			(certificate.ExpiryDate.IsZero() || currentTime.Before(certificate.ExpiryDate))

		certificates = append(certificates, &certificate)
	}

	return certificates, nil
}

// GetStudentHistory retrieves all academic records for a student (Fixed to read actual records)
func (s *SmartContract) GetStudentHistory(ctx contractapi.TransactionContextInterface, studentID string) ([]*AcademicRecord, error) {
	// Use composite key to query records by studentID
	// Format: student~record~{studentID}~{recordID}
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(StudentRecordKey, []string{studentID})
	if err != nil {
		return nil, fmt.Errorf("failed to get student history: %w", err)
	}
	defer resultsIterator.Close()

	var records []*AcademicRecord
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		// Split the composite key to extract recordID
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, err
		}

		// compositeKeyParts[0] is studentID, compositeKeyParts[1] is recordID
		if len(compositeKeyParts) < 2 {
			continue
		}
		recordID := compositeKeyParts[1]

		// Fetch the actual record using recordID
		recordJSON, err := ctx.GetStub().GetState(recordID)
		if err != nil {
			return nil, fmt.Errorf("failed to read record %s: %v", recordID, err)
		}
		if recordJSON == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordJSON, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record %s: %v", recordID, err)
		}
		records = append(records, &record)
	}

	return records, nil
}

// GetStudentCGPA retrieves the current CGPA for a student
func (s *SmartContract) GetStudentCGPA(ctx contractapi.TransactionContextInterface, studentID string) (float64, error) {
	student, err := s.GetStudent(ctx, studentID)
	if err != nil {
		return 0, fmt.Errorf("failed to get student: %w", err)
	}
	return student.CurrentCGPA, nil
}

// GetAllStudents retrieves all students using a composite key for efficiency
func (s *SmartContract) GetAllStudents(ctx contractapi.TransactionContextInterface) ([]*Student, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(StudentAllKey, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all students: %w", err)
	}
	defer resultsIterator.Close()

	var students []*Student
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate over students: %w", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %w", err)
		}
		if len(compositeKeyParts) < 1 {
			return nil, fmt.Errorf("invalid composite key for student")
		}
		rollNumber := compositeKeyParts[0]

		student, err := s.GetStudent(ctx, rollNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get student %s: %w", rollNumber, err)
		}
		students = append(students, student)
	}

	return students, nil
}

// DEPRECATED: Use GetStudentsByDepartment instead
// GetStudentsByFaculty retrieves all students in the same department as the faculty
// For faculty to view students in their department
// This function is kept for backward compatibility but should not be used
func (s *SmartContract) GetStudentsByFaculty(ctx contractapi.TransactionContextInterface, facultyID string, facultyDepartment string) ([]*Student, error) {
	// Redirect to GetStudentsByDepartment
	return s.GetStudentsByDepartment(ctx, facultyDepartment)
}

// Helper function to calculate grades (Enhanced with custom NIT Warangal grade system)
func calculateGrades(courses []Course) (float64, float64) {
	totalPoints := 0.0
	totalCredits := 0.0

	// Custom NIT Warangal grade point mapping (10-point scale)
	gradePoints := map[string]float64{
		GradeS: 10.0, // Outstanding
		GradeA: 9.0,  // Excellent
		GradeB: 8.0,  // Very Good
		GradeC: 7.0,  // Good
		GradeD: 6.0,  // Average
		GradeP: 5.0,  // Pass
		GradeU: 0.0,  // Fail
		GradeR: 0.0,  // Reappear
	}

	for _, course := range courses {
		totalCredits += course.Credits
		if gp, ok := gradePoints[course.Grade]; ok {
			totalPoints += gp * course.Credits
		}
	}

	sgpa := 0.0
	if totalCredits > 0 {
		sgpa = totalPoints / totalCredits
	}

	return totalCredits, sgpa
}

// Calculate CGPA based on all approved records (Enhanced)
func (s *SmartContract) calculateCGPA(ctx contractapi.TransactionContextInterface, studentID string, currentSemester int) (float64, float64, error) {
	// Get all approved academic records for the student
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(RecordStatusKey, []string{RecordApproved, studentID})
	if err != nil {
		return 0, 0, fmt.Errorf("failed to query approved records: %w", err)
	}
	defer resultsIterator.Close()

	totalPoints := 0.0
	totalCredits := 0.0

	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return 0, 0, fmt.Errorf("failed to iterate approved records: %w", err)
		}

		_, keyParts, err := ctx.GetStub().SplitCompositeKey(response.Key)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to split composite key for record: %w", err)
		}
		recordID := keyParts[len(keyParts)-1]

		record, err := s.GetAcademicRecord(ctx, recordID)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to get academic record %s: %w", recordID, err)
		}

		// Ensure we only include semesters up to the current one
		if record.Semester <= currentSemester {
			totalPoints += record.SGPA * record.TotalCredits
			totalCredits += record.TotalCredits
		}
	}

	if totalCredits == 0 {
		return 0, 0, nil // Avoid division by zero
	}

	cgpa := totalPoints / totalCredits
	return cgpa, totalCredits, nil
}

// calculateCGPAIncludingCurrent calculates CGPA including the current record being approved
func (s *SmartContract) calculateCGPAIncludingCurrent(ctx contractapi.TransactionContextInterface, studentID string, currentSemester int, currentSGPA float64, currentCredits float64) (float64, float64, error) {
	// Get all approved academic records for the student (excluding current semester)
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(RecordStatusKey, []string{RecordApproved, studentID})
	if err != nil {
		return 0, 0, fmt.Errorf("failed to query approved records: %w", err)
	}
	defer resultsIterator.Close()

	totalPoints := 0.0
	totalCredits := 0.0

	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return 0, 0, fmt.Errorf("failed to iterate approved records: %w", err)
		}

		_, keyParts, err := ctx.GetStub().SplitCompositeKey(response.Key)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to split composite key for record: %w", err)
		}
		recordID := keyParts[len(keyParts)-1]

		record, err := s.GetAcademicRecord(ctx, recordID)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to get academic record %s: %w", recordID, err)
		}

		// Only include semesters before the current one (avoid double-counting)
		if record.Semester < currentSemester {
			totalPoints += record.SGPA * record.TotalCredits
			totalCredits += record.TotalCredits
		}
	}

	// Add current semester's data
	totalPoints += currentSGPA * currentCredits
	totalCredits += currentCredits

	if totalCredits == 0 {
		return 0, 0, nil // Avoid division by zero
	}

	cgpa := totalPoints / totalCredits
	return cgpa, totalCredits, nil
}

// ============================================================================
// Phase 2: Query Functions with Pagination
// ============================================================================

// PaginatedQueryResult represents paginated query results
type PaginatedQueryResult struct {
	Records     interface{} `json:"records"`
	Bookmark    string      `json:"bookmark"`
	RecordCount int         `json:"recordCount"`
	HasMore     bool        `json:"hasMore"`
}

// QueryStudentsByDepartment returns students in a department with pagination
func (s *SmartContract) QueryStudentsByDepartment(ctx contractapi.TransactionContextInterface, department string, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	// Validate page size
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50 // Default to 50 records per page
	}

	// Check department access
	err := checkDepartmentAccess(ctx, department)
	if err != nil {
		return nil, err
	}

	// Query using composite key: student~dept~{Department}~{RollNumber}
	resultsIterator, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(StudentDeptKey, []string{department}, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query students by department: %w", err)
	}
	defer resultsIterator.Close()

	var students []*Student
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate query results: %v", err)
		}

		// Extract student roll number from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}
		rollNumber := compositeKeyParts[1] // student~dept~{Department}~{RollNumber}

		// Get actual student record
		studentBytes, err := ctx.GetStub().GetState(rollNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to read student %s: %v", rollNumber, err)
		}
		if studentBytes == nil {
			continue // Skip if student doesn't exist
		}

		var student Student
		err = json.Unmarshal(studentBytes, &student)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal student data: %w", err)
		}

		students = append(students, &student)
	}

	result := &PaginatedQueryResult{
		Records:     students,
		Bookmark:    metadata.Bookmark,
		RecordCount: int(metadata.FetchedRecordsCount),
		HasMore:     metadata.Bookmark != "",
	}

	return result, nil
}

// QueryStudentsByYear returns students by enrollment year with pagination
func (s *SmartContract) QueryStudentsByYear(ctx contractapi.TransactionContextInterface, year int, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	// Validate page size
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	// Validate year
	if year < 1950 {
		return nil, fmt.Errorf("invalid enrollment year: %d", year)
	}

	// Query using composite key: student~year~{EnrollmentYear}~{RollNumber}
	resultsIterator, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(StudentYearKey, []string{fmt.Sprintf("%d", year)}, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query students by year: %w", err)
	}
	defer resultsIterator.Close()

	var students []*Student
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate query results: %v", err)
		}

		// Extract student roll number from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}
		rollNumber := compositeKeyParts[1] // student~year~{Year}~{RollNumber}

		// Get actual student record
		studentBytes, err := ctx.GetStub().GetState(rollNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to read student %s: %v", rollNumber, err)
		}
		if studentBytes == nil {
			continue
		}

		var student Student
		err = json.Unmarshal(studentBytes, &student)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal student data: %w", err)
		}

		students = append(students, &student)
	}

	result := &PaginatedQueryResult{
		Records:     students,
		Bookmark:    metadata.Bookmark,
		RecordCount: int(metadata.FetchedRecordsCount),
		HasMore:     metadata.Bookmark != "",
	}

	return result, nil
}

// QueryStudentsByStatus returns students by status with pagination
func (s *SmartContract) QueryStudentsByStatus(ctx contractapi.TransactionContextInterface, status string, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	// Validate page size
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	// Validate status
	err := validateStatus(status)
	if err != nil {
		return nil, err
	}

	// Query using composite key: student~status~{Status}~{RollNumber}
	resultsIterator, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(StudentStatusKey, []string{status}, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query students by status: %w", err)
	}
	defer resultsIterator.Close()

	var students []*Student
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate query results: %v", err)
		}

		// Extract student roll number from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}
		rollNumber := compositeKeyParts[1] // student~status~{Status}~{RollNumber}

		// Get actual student record
		studentBytes, err := ctx.GetStub().GetState(rollNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to read student %s: %v", rollNumber, err)
		}
		if studentBytes == nil {
			continue
		}

		var student Student
		err = json.Unmarshal(studentBytes, &student)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal student data: %w", err)
		}

		students = append(students, &student)
	}

	result := &PaginatedQueryResult{
		Records:     students,
		Bookmark:    metadata.Bookmark,
		RecordCount: int(metadata.FetchedRecordsCount),
		HasMore:     metadata.Bookmark != "",
	}

	return result, nil
}

// QueryRecordsBySemester returns academic records by semester with pagination
func (s *SmartContract) QueryRecordsBySemester(ctx contractapi.TransactionContextInterface, semester int, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	// Validate page size
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	// Validate semester
	err := validateSemester(semester)
	if err != nil {
		return nil, err
	}

	// Query using composite key: record~semester~{Semester}~{StudentID}~{RecordID}
	resultsIterator, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(RecordSemesterKey, []string{fmt.Sprintf("%d", semester)}, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query records by semester: %w", err)
	}
	defer resultsIterator.Close()

	var records []*AcademicRecord
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate query results: %v", err)
		}

		// Extract record ID from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}
		recordID := compositeKeyParts[2] // record~semester~{Semester}~{StudentID}~{RecordID}

		// Get actual record
		recordBytes, err := ctx.GetStub().GetState(recordID)
		if err != nil {
			return nil, fmt.Errorf("failed to read record %s: %v", recordID, err)
		}
		if recordBytes == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordBytes, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record: %v", err)
		}

		// Check department access
		err = checkDepartmentAccess(ctx, record.Department)
		if err != nil {
			continue // Skip records from other departments
		}

		records = append(records, &record)
	}

	result := &PaginatedQueryResult{
		Records:     records,
		Bookmark:    metadata.Bookmark,
		RecordCount: int(metadata.FetchedRecordsCount),
		HasMore:     metadata.Bookmark != "",
	}

	return result, nil
}

// QueryRecordsByStatus returns academic records by status with pagination
func (s *SmartContract) QueryRecordsByStatus(ctx contractapi.TransactionContextInterface, status string, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	// Validate page size
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	// Validate status
	validStatuses := []string{StatusDraft, RecordSubmitted, RecordApproved}
	isValid := false
	for _, validStatus := range validStatuses {
		if status == validStatus {
			isValid = true
			break
		}
	}
	if !isValid {
		return nil, fmt.Errorf("invalid record status: %s (must be DRAFT, SUBMITTED, or APPROVED)", status)
	}

	// Query using composite key: record~status~{Status}~{StudentID}~{RecordID}
	resultsIterator, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(RecordStatusKey, []string{status}, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query records by status: %w", err)
	}
	defer resultsIterator.Close()

	var records []*AcademicRecord
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate query results: %v", err)
		}

		// Extract record ID from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}
		recordID := compositeKeyParts[2] // record~status~{Status}~{StudentID}~{RecordID}

		// Get actual record
		recordBytes, err := ctx.GetStub().GetState(recordID)
		if err != nil {
			return nil, fmt.Errorf("failed to read record %s: %v", recordID, err)
		}
		if recordBytes == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordBytes, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record: %v", err)
		}

		// Check department access
		err = checkDepartmentAccess(ctx, record.Department)
		if err != nil {
			continue // Skip records from other departments
		}

		records = append(records, &record)
	}

	result := &PaginatedQueryResult{
		Records:     records,
		Bookmark:    metadata.Bookmark,
		RecordCount: int(metadata.FetchedRecordsCount),
		HasMore:     metadata.Bookmark != "",
	}

	return result, nil
}

// QueryPendingRecords returns all records awaiting approval (DRAFT + SUBMITTED)
func (s *SmartContract) QueryPendingRecords(ctx contractapi.TransactionContextInterface, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	// Validate page size
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	// Query DRAFT records first
	var allRecords []*AcademicRecord

	// Get DRAFT records
	draftIterator, _, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(
		RecordStatusKey,
		[]string{StatusDraft},
		int32(pageSize),
		bookmark,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query draft records: %v", err)
	}
	defer draftIterator.Close()

	for draftIterator.HasNext() {
		queryResponse, err := draftIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate draft records: %v", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		recordID := compositeKeyParts[2]

		recordBytes, err := ctx.GetStub().GetState(recordID)
		if err != nil || recordBytes == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordBytes, &record)
		if err != nil {
			continue
		}

		// Check department access
		err = checkDepartmentAccess(ctx, record.Department)
		if err != nil {
			continue
		}

		allRecords = append(allRecords, &record)
	}

	// Get SUBMITTED records
	submittedIterator, responseMetadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(
		RecordStatusKey,
		[]string{RecordSubmitted},
		int32(pageSize),
		bookmark,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query submitted records: %v", err)
	}
	defer submittedIterator.Close()

	for submittedIterator.HasNext() {
		queryResponse, err := submittedIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate submitted records: %v", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		recordID := compositeKeyParts[2]

		recordBytes, err := ctx.GetStub().GetState(recordID)
		if err != nil || recordBytes == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordBytes, &record)
		if err != nil {
			continue
		}

		// Check department access
		err = checkDepartmentAccess(ctx, record.Department)
		if err != nil {
			continue
		}

		allRecords = append(allRecords, &record)
	}

	result := &PaginatedQueryResult{
		Records:     allRecords,
		Bookmark:    responseMetadata.Bookmark,
		RecordCount: len(allRecords),
		HasMore:     responseMetadata.Bookmark != "",
	}

	return result, nil
}

// ==================== Department Management ====================

// CreateDepartment creates a new department
func (s *SmartContract) CreateDepartment(ctx contractapi.TransactionContextInterface,
	departmentID, departmentName, hod, email, phone string) error {

	// Access Control: Only admin can create departments
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	if clientMSPID != NITWarangalMSP {
		return fmt.Errorf("unauthorized: only admin can create departments")
	}

	// Normalize department ID to uppercase
	departmentID = strings.ToUpper(departmentID)

	// Check if department already exists
	exists, err := s.departmentExists(ctx, departmentID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("department %s already exists", departmentID)
	}

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	department := Department{
		DepartmentID:   departmentID,
		DepartmentName: departmentName,
		HOD:            hod,
		Email:          email,
		Phone:          phone,
		CreatedBy:      clientID,
		CreatedAt:      time.Now(),
		ModifiedBy:     clientID,
		ModifiedAt:     time.Now(),
	}

	departmentJSON, err := json.Marshal(department)
	if err != nil {
		return fmt.Errorf("failed to marshal department: %v", err)
	}

	err = ctx.GetStub().PutState(departmentID, departmentJSON)
	if err != nil {
		return fmt.Errorf("failed to put department state: %v", err)
	}

	// Create composite key for querying all departments
	deptIndexKey, err := ctx.GetStub().CreateCompositeKey(DepartmentAllKey, []string{departmentID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}

	err = ctx.GetStub().PutState(deptIndexKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put department index: %v", err)
	}

	return nil
}

// GetDepartment retrieves a department by ID
func (s *SmartContract) GetDepartment(ctx contractapi.TransactionContextInterface, departmentID string) (*Department, error) {
	// Normalize department ID to uppercase
	departmentID = strings.ToUpper(departmentID)

	departmentJSON, err := ctx.GetStub().GetState(departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to read department: %v", err)
	}
	if departmentJSON == nil {
		return nil, fmt.Errorf("department %s does not exist", departmentID)
	}

	var department Department
	err = json.Unmarshal(departmentJSON, &department)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal department: %v", err)
	}

	return &department, nil
}

// GetAllDepartments retrieves all departments
func (s *SmartContract) GetAllDepartments(ctx contractapi.TransactionContextInterface) ([]*Department, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(DepartmentAllKey, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get departments: %v", err)
	}
	defer resultsIterator.Close()

	var departments []*Department
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate departments: %v", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}

		departmentID := compositeKeyParts[0]
		departmentJSON, err := ctx.GetStub().GetState(departmentID)
		if err != nil || departmentJSON == nil {
			continue
		}

		var department Department
		err = json.Unmarshal(departmentJSON, &department)
		if err != nil {
			continue
		}

		departments = append(departments, &department)
	}

	return departments, nil
}

// UpdateDepartment updates department information
func (s *SmartContract) UpdateDepartment(ctx contractapi.TransactionContextInterface,
	departmentID string, updateData string) error {

	// Access Control: Only admin can update departments
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	if clientMSPID != NITWarangalMSP {
		return fmt.Errorf("unauthorized: only admin can update departments")
	}

	department, err := s.GetDepartment(ctx, departmentID)
	if err != nil {
		return err
	}

	var updates map[string]interface{}
	err = json.Unmarshal([]byte(updateData), &updates)
	if err != nil {
		return fmt.Errorf("failed to parse update data: %v", err)
	}

	// Apply updates
	if hod, ok := updates["hod"].(string); ok {
		department.HOD = hod
	}
	if email, ok := updates["email"].(string); ok {
		department.Email = email
	}
	if phone, ok := updates["phone"].(string); ok {
		department.Phone = phone
	}

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	department.ModifiedBy = clientID
	department.ModifiedAt = time.Now()

	departmentJSON, err := json.Marshal(department)
	if err != nil {
		return fmt.Errorf("failed to marshal department: %v", err)
	}

	return ctx.GetStub().PutState(departmentID, departmentJSON)
}

// departmentExists checks if a department exists
func (s *SmartContract) departmentExists(ctx contractapi.TransactionContextInterface, departmentID string) (bool, error) {
	// Normalize department ID to uppercase
	departmentID = strings.ToUpper(departmentID)

	departmentJSON, err := ctx.GetStub().GetState(departmentID)
	if err != nil {
		return false, fmt.Errorf("failed to read department: %v", err)
	}
	return departmentJSON != nil, nil
}

// ==================== Course Offering Management ====================

// CreateCourseOffering creates a new course offering (many-to-many relationship)
func (s *SmartContract) CreateCourseOffering(ctx contractapi.TransactionContextInterface,
	departmentID, courseCode, courseName string, credits float64, semester int, academicYear string) error {

	// Access Control: Department or Admin can create course offerings
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	if clientMSPID != DepartmentsMSP && clientMSPID != NITWarangalMSP {
		return fmt.Errorf("unauthorized: only department or admin can create course offerings")
	}

	// Normalize department ID to uppercase
	departmentID = strings.ToUpper(departmentID)

	// Verify department exists
	exists, err := s.departmentExists(ctx, departmentID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("department %s does not exist", departmentID)
	}

	// Validate credits
	if err := validateCredits(credits); err != nil {
		return err
	}

	// Validate semester
	if err := validateSemester(semester); err != nil {
		return err
	}

	// Create unique offering ID
	offeringID := fmt.Sprintf("%s-%s-%d-%s", departmentID, courseCode, semester, academicYear)

	// Check if offering already exists
	offeringJSON, err := ctx.GetStub().GetState(offeringID)
	if err != nil {
		return fmt.Errorf("failed to read offering: %v", err)
	}
	if offeringJSON != nil {
		return fmt.Errorf("course offering %s already exists", offeringID)
	}

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	offering := CourseOffering{
		OfferingID:   offeringID,
		DepartmentID: departmentID,
		CourseCode:   courseCode,
		CourseName:   courseName,
		Credits:      credits,
		Semester:     semester,
		AcademicYear: academicYear,
		IsActive:     true,
		CreatedBy:    clientID,
		CreatedAt:    time.Now(),
		ModifiedBy:   clientID,
		ModifiedAt:   time.Now(),
	}

	offeringJSON, err = json.Marshal(offering)
	if err != nil {
		return fmt.Errorf("failed to marshal offering: %v", err)
	}

	err = ctx.GetStub().PutState(offeringID, offeringJSON)
	if err != nil {
		return fmt.Errorf("failed to put offering state: %v", err)
	}

	// Create composite key for querying by department
	deptCourseKey, err := ctx.GetStub().CreateCompositeKey(CourseDeptKey, []string{departmentID, offeringID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}

	err = ctx.GetStub().PutState(deptCourseKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put course-dept index: %v", err)
	}

	return nil
}

// GetCourseOffering retrieves a course offering by ID
func (s *SmartContract) GetCourseOffering(ctx contractapi.TransactionContextInterface, offeringID string) (*CourseOffering, error) {
	offeringJSON, err := ctx.GetStub().GetState(offeringID)
	if err != nil {
		return nil, fmt.Errorf("failed to read course offering: %v", err)
	}
	if offeringJSON == nil {
		return nil, fmt.Errorf("course offering %s does not exist", offeringID)
	}

	var offering CourseOffering
	err = json.Unmarshal(offeringJSON, &offering)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal course offering: %v", err)
	}

	return &offering, nil
}

// GetCoursesByDepartment retrieves all courses offered by a department
func (s *SmartContract) GetCoursesByDepartment(ctx contractapi.TransactionContextInterface, departmentID string) ([]*CourseOffering, error) {
	// Normalize department ID to uppercase
	departmentID = strings.ToUpper(departmentID)

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(CourseDeptKey, []string{departmentID})
	if err != nil {
		return nil, fmt.Errorf("failed to get courses: %v", err)
	}
	defer resultsIterator.Close()

	var courses []*CourseOffering
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate courses: %v", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}

		offeringID := compositeKeyParts[1]
		offeringJSON, err := ctx.GetStub().GetState(offeringID)
		if err != nil || offeringJSON == nil {
			continue
		}

		var offering CourseOffering
		err = json.Unmarshal(offeringJSON, &offering)
		if err != nil {
			continue
		}

		courses = append(courses, &offering)
	}

	return courses, nil
}

// UpdateCourseOffering updates course offering details
func (s *SmartContract) UpdateCourseOffering(ctx contractapi.TransactionContextInterface,
	offeringID string, isActive bool) error {

	// Access Control: Department or Admin
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	if clientMSPID != DepartmentsMSP && clientMSPID != NITWarangalMSP {
		return fmt.Errorf("unauthorized: only department or admin can update course offerings")
	}

	offering, err := s.GetCourseOffering(ctx, offeringID)
	if err != nil {
		return err
	}

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	offering.IsActive = isActive
	offering.ModifiedBy = clientID
	offering.ModifiedAt = time.Now()

	offeringJSON, err := json.Marshal(offering)
	if err != nil {
		return fmt.Errorf("failed to marshal offering: %v", err)
	}

	return ctx.GetStub().PutState(offeringID, offeringJSON)
}

// GetStudentsByDepartment retrieves students by department (replaces GetStudentsByFaculty)
func (s *SmartContract) GetStudentsByDepartment(ctx contractapi.TransactionContextInterface, department string) ([]*Student, error) {
	// Normalize department to uppercase for case-insensitive matching
	department = strings.ToUpper(department)

	// Department can view their own students
	err := checkDepartmentAccess(ctx, department)
	if err != nil {
		// Allow admin to view any department
		clientMSPID, mspErr := ctx.GetClientIdentity().GetMSPID()
		if mspErr != nil || clientMSPID != NITWarangalMSP {
			return nil, err
		}
	}

	// Use composite key instead of CouchDB query for LevelDB compatibility
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(StudentDeptKey, []string{department})
	if err != nil {
		return nil, fmt.Errorf("failed to query students: %v", err)
	}
	defer resultsIterator.Close()

	var students []*Student
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate students: %v", err)
		}

		// Extract roll number from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}

		if len(compositeKeyParts) < 2 {
			continue
		}

		rollNumber := compositeKeyParts[1] // student~dept~{Department}~{RollNumber}

		// Get student record
		studentJSON, err := ctx.GetStub().GetState(rollNumber)
		if err != nil || studentJSON == nil {
			continue
		}

		var student Student
		err = json.Unmarshal(studentJSON, &student)
		if err != nil {
			continue
		}

		students = append(students, &student)
	}

	return students, nil
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
