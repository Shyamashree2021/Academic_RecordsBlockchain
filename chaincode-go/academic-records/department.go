package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

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

	departments := make([]*Department, 0)
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

	courses := make([]*CourseOffering, 0)
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
