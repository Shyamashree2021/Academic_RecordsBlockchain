package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

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

	// Access Control: VerifiersMSP can read public student info
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get client MSP ID: %v", err)
	}
	if clientMSPID == VerifiersMSP {
		return &student, nil
	}

	// For other MSPs, check department access
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

// GetAllStudents retrieves all students using a composite key for efficiency
func (s *SmartContract) GetAllStudents(ctx contractapi.TransactionContextInterface) ([]*Student, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(StudentAllKey, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all students: %w", err)
	}
	defer resultsIterator.Close()

	students := make([]*Student, 0)
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

// GetStudentHistory retrieves all academic records for a student (Fixed to read actual records)
func (s *SmartContract) GetStudentHistory(ctx contractapi.TransactionContextInterface, studentID string) ([]*AcademicRecord, error) {
	// Access Control: NITWarangalMSP, DepartmentsMSP, or VerifiersMSP
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get client MSP ID: %v", err)
	}
	if clientMSPID != NITWarangalMSP && clientMSPID != DepartmentsMSP && clientMSPID != VerifiersMSP {
		return nil, fmt.Errorf("unauthorized: only NITWarangalMSP, DepartmentsMSP, or VerifiersMSP can access student history")
	}

	// Use composite key to query records by studentID
	// Format: student~record~{studentID}~{recordID}
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(StudentRecordKey, []string{studentID})
	if err != nil {
		return nil, fmt.Errorf("failed to get student history: %w", err)
	}
	defer resultsIterator.Close()

	records := make([]*AcademicRecord, 0)
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

	students := make([]*Student, 0)
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
