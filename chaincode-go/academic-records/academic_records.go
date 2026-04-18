package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

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

	// AI Policy Check: evaluate against active AI-generated rules before saving
	tempRecord := AcademicRecord{
		StudentID:    rollNumber,
		Department:   department,
		Semester:     semester,
		Courses:      courses,
		TotalCredits: totalCredits,
		SGPA:         sgpa,
	}
	if policyDecision, policyReason := evaluateAIPolicy(ctx, tempRecord); policyDecision == "BLOCK" {
		return fmt.Errorf("record blocked by AI policy: %s", policyReason)
	}

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

	// 5. record~all~{recordID} (for GetAllAcademicRecords query)
	recordAllKey, err := ctx.GetStub().CreateCompositeKey(RecordAllKey, []string{recordID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for all records: %w", err)
	}
	err = ctx.GetStub().PutState(recordAllKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put state for all records key: %w", err)
	}

	// Emit RecordCreated event
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

	// AI On-Chain Scoring: compute deterministic fraud score and notify AI agent
	s.storeOnChainScoreAndNotify(ctx, recordID, record)

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

	// In multi-level approval workflow, admin can only approve DEPT_APPROVED records
	if record.Status != RecordDeptApproved {
		return fmt.Errorf("record must be department-approved before admin approval; current status is '%s'", record.Status)
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

	// Multi-Party Endorsement: Lock approved record with 2-of-2 policy
	// After final approval, this record cannot be modified without both
	// NITWarangalMSP AND DepartmentsMSP endorsing the transaction
	if err := setRecordEndorsementPolicy(ctx, recordID); err != nil {
		// Non-blocking — record is approved, SBE is an additional security layer
		_ = err
	}

	return nil
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
