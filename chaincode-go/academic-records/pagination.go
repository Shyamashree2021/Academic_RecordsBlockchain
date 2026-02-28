package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

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

	students := make([]*Student, 0)
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

	students := make([]*Student, 0)
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

	students := make([]*Student, 0)
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

	records := make([]*AcademicRecord, 0)
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
	validStatuses := []string{StatusDraft, RecordSubmitted, RecordDeptApproved, RecordApproved, RecordRejected}
	isValid := false
	for _, validStatus := range validStatuses {
		if status == validStatus {
			isValid = true
			break
		}
	}
	if !isValid {
		return nil, fmt.Errorf("invalid record status: %s (must be DRAFT, SUBMITTED, DEPT_APPROVED, APPROVED, or REJECTED)", status)
	}

	// Query using composite key: record~status~{Status}~{StudentID}~{RecordID}
	resultsIterator, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(RecordStatusKey, []string{status}, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query records by status: %w", err)
	}
	defer resultsIterator.Close()

	records := make([]*AcademicRecord, 0)
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

// QueryPendingRecords returns all records awaiting approval (DRAFT + SUBMITTED + DEPT_APPROVED)
func (s *SmartContract) QueryPendingRecords(ctx contractapi.TransactionContextInterface, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	// Validate page size
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	// Query DRAFT records first
	allRecords := make([]*AcademicRecord, 0)

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
	submittedIterator, _, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(
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

	// Get DEPT_APPROVED records (awaiting final admin approval)
	deptApprovedIterator, responseMetadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(
		RecordStatusKey,
		[]string{RecordDeptApproved},
		int32(pageSize),
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query dept-approved records: %v", err)
	}
	defer deptApprovedIterator.Close()

	for deptApprovedIterator.HasNext() {
		queryResponse, err := deptApprovedIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate dept-approved records: %v", err)
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
