package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// CreateFaculty creates a new faculty member profile
func (s *SmartContract) CreateFaculty(ctx contractapi.TransactionContextInterface,
	facultyID, name, department, designation, email, phone, specialization string, joiningYear int) error {

	// Access Control: Only NITWarangalMSP can create faculty
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	department = strings.ToUpper(department)

	if len(facultyID) < 3 || len(facultyID) > 20 {
		return fmt.Errorf("faculty ID must be between 3 and 20 characters")
	}
	if len(name) < 3 || len(name) > 100 {
		return fmt.Errorf("name must be between 3 and 100 characters")
	}
	currentYear := time.Now().Year()
	if joiningYear < 1950 || joiningYear > currentYear+1 {
		return fmt.Errorf("invalid joining year %d", joiningYear)
	}

	exists, err := s.facultyExists(ctx, facultyID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("faculty with ID %s already exists", facultyID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %w", err)
	}

	faculty := Faculty{
		FacultyID:      facultyID,
		Name:           name,
		Department:     department,
		Designation:    designation,
		Email:          email,
		Phone:          phone,
		Specialization: specialization,
		JoiningYear:    joiningYear,
		Status:         FacultyActive,
		CreatedBy:      clientID,
		CreatedAt:      timestamp,
		ModifiedBy:     clientID,
		ModifiedAt:     timestamp,
	}

	facultyJSON, err := json.Marshal(faculty)
	if err != nil {
		return fmt.Errorf("failed to marshal faculty: %w", err)
	}

	err = ctx.GetStub().PutState(facultyID, facultyJSON)
	if err != nil {
		return fmt.Errorf("failed to put faculty state: %w", err)
	}

	// Composite key: faculty~all~{facultyID}
	allKey, err := ctx.GetStub().CreateCompositeKey(FacultyAllKey, []string{facultyID})
	if err != nil {
		return fmt.Errorf("failed to create faculty all composite key: %w", err)
	}
	err = ctx.GetStub().PutState(allKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put faculty all key: %w", err)
	}

	// Composite key: faculty~dept~{department}~{facultyID}
	deptKey, err := ctx.GetStub().CreateCompositeKey(FacultyDeptKey, []string{department, facultyID})
	if err != nil {
		return fmt.Errorf("failed to create faculty dept composite key: %w", err)
	}
	err = ctx.GetStub().PutState(deptKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put faculty dept key: %w", err)
	}

	eventPayload := map[string]interface{}{
		"facultyID":   facultyID,
		"name":        name,
		"department":  department,
		"designation": designation,
		"createdBy":   clientID,
		"createdAt":   timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("FacultyCreated", eventJSON)

	return nil
}

// GetFaculty retrieves a faculty member profile by ID
func (s *SmartContract) GetFaculty(ctx contractapi.TransactionContextInterface, facultyID string) (*Faculty, error) {
	facultyJSON, err := ctx.GetStub().GetState(facultyID)
	if err != nil {
		return nil, fmt.Errorf("failed to read faculty: %v", err)
	}
	if facultyJSON == nil {
		return nil, fmt.Errorf("faculty %s does not exist", facultyID)
	}

	var faculty Faculty
	err = json.Unmarshal(facultyJSON, &faculty)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal faculty: %v", err)
	}

	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get client MSP ID: %v", err)
	}

	if clientMSPID == NITWarangalMSP {
		return &faculty, nil
	}

	if clientMSPID == DepartmentsMSP {
		err = checkDepartmentAccess(ctx, faculty.Department)
		if err != nil {
			return nil, err
		}
		return &faculty, nil
	}

	return nil, fmt.Errorf("unauthorized: only NITWarangalMSP or DepartmentsMSP can read faculty profiles")
}

// GetAllFaculty retrieves all faculty members
func (s *SmartContract) GetAllFaculty(ctx contractapi.TransactionContextInterface) ([]*Faculty, error) {
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return nil, err
	}

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(FacultyAllKey, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all faculty: %w", err)
	}
	defer resultsIterator.Close()

	facultyList := make([]*Faculty, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate faculty: %w", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		if len(compositeKeyParts) < 1 {
			continue
		}
		facultyID := compositeKeyParts[0]

		facultyJSON, err := ctx.GetStub().GetState(facultyID)
		if err != nil || facultyJSON == nil {
			continue
		}

		var faculty Faculty
		err = json.Unmarshal(facultyJSON, &faculty)
		if err != nil {
			continue
		}
		facultyList = append(facultyList, &faculty)
	}

	return facultyList, nil
}

// UpdateFaculty updates a faculty member's profile
func (s *SmartContract) UpdateFaculty(ctx contractapi.TransactionContextInterface,
	facultyID string, updateData string) error {

	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	faculty, err := s.GetFaculty(ctx, facultyID)
	if err != nil {
		return err
	}

	var updates map[string]interface{}
	err = json.Unmarshal([]byte(updateData), &updates)
	if err != nil {
		return fmt.Errorf("failed to parse update data: %v", err)
	}

	oldDepartment := faculty.Department

	if name, ok := updates["name"].(string); ok && len(name) >= 3 {
		faculty.Name = name
	}
	if department, ok := updates["department"].(string); ok {
		faculty.Department = strings.ToUpper(department)
	}
	if designation, ok := updates["designation"].(string); ok {
		faculty.Designation = designation
	}
	if email, ok := updates["email"].(string); ok {
		faculty.Email = email
	}
	if phone, ok := updates["phone"].(string); ok {
		faculty.Phone = phone
	}
	if specialization, ok := updates["specialization"].(string); ok {
		faculty.Specialization = specialization
	}
	if status, ok := updates["status"].(string); ok {
		if err := validateFacultyStatus(status); err != nil {
			return err
		}
		faculty.Status = status
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	faculty.ModifiedBy = clientID
	faculty.ModifiedAt = timestamp

	facultyJSON, err := json.Marshal(faculty)
	if err != nil {
		return fmt.Errorf("failed to marshal faculty: %v", err)
	}

	err = ctx.GetStub().PutState(facultyID, facultyJSON)
	if err != nil {
		return fmt.Errorf("failed to put faculty state: %v", err)
	}

	// If department changed, update composite keys
	if oldDepartment != faculty.Department {
		oldDeptKey, err := ctx.GetStub().CreateCompositeKey(FacultyDeptKey, []string{oldDepartment, facultyID})
		if err == nil {
			ctx.GetStub().DelState(oldDeptKey)
		}
		newDeptKey, err := ctx.GetStub().CreateCompositeKey(FacultyDeptKey, []string{faculty.Department, facultyID})
		if err != nil {
			return fmt.Errorf("failed to create new faculty dept key: %w", err)
		}
		err = ctx.GetStub().PutState(newDeptKey, []byte{0x00})
		if err != nil {
			return fmt.Errorf("failed to put new faculty dept key: %w", err)
		}
	}

	eventPayload := map[string]interface{}{
		"facultyID":  facultyID,
		"modifiedBy": clientID,
		"modifiedAt": timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("FacultyUpdated", eventJSON)

	return nil
}

// GetFacultyByDepartment retrieves all faculty in a specific department
func (s *SmartContract) GetFacultyByDepartment(ctx contractapi.TransactionContextInterface, department string) ([]*Faculty, error) {
	department = strings.ToUpper(department)

	err := checkDepartmentAccess(ctx, department)
	if err != nil {
		return nil, err
	}

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(FacultyDeptKey, []string{department})
	if err != nil {
		return nil, fmt.Errorf("failed to get faculty by department: %w", err)
	}
	defer resultsIterator.Close()

	facultyList := make([]*Faculty, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate faculty: %w", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		if len(compositeKeyParts) < 2 {
			continue
		}
		facultyID := compositeKeyParts[1]

		facultyJSON, err := ctx.GetStub().GetState(facultyID)
		if err != nil || facultyJSON == nil {
			continue
		}

		var faculty Faculty
		err = json.Unmarshal(facultyJSON, &faculty)
		if err != nil {
			continue
		}
		facultyList = append(facultyList, &faculty)
	}

	return facultyList, nil
}
