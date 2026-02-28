package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// GetAllAcademicRecords retrieves all academic records
func (s *SmartContract) GetAllAcademicRecords(ctx contractapi.TransactionContextInterface) ([]*AcademicRecord, error) {
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return nil, err
	}

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(RecordAllKey, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all records: %w", err)
	}
	defer resultsIterator.Close()

	records := make([]*AcademicRecord, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate records: %w", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		if len(compositeKeyParts) < 1 {
			continue
		}
		recordID := compositeKeyParts[0]

		recordJSON, err := ctx.GetStub().GetState(recordID)
		if err != nil || recordJSON == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordJSON, &record)
		if err != nil {
			continue
		}
		records = append(records, &record)
	}

	return records, nil
}

// GetRecordsBySemester retrieves all academic records for a given semester (non-paginated)
func (s *SmartContract) GetRecordsBySemester(ctx contractapi.TransactionContextInterface, semester int) ([]*AcademicRecord, error) {
	if err := validateSemester(semester); err != nil {
		return nil, err
	}

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(RecordSemesterKey, []string{fmt.Sprintf("%d", semester)})
	if err != nil {
		return nil, fmt.Errorf("failed to get records by semester: %w", err)
	}
	defer resultsIterator.Close()

	records := make([]*AcademicRecord, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate records: %w", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		if len(compositeKeyParts) < 3 {
			continue
		}
		recordID := compositeKeyParts[2]

		recordJSON, err := ctx.GetStub().GetState(recordID)
		if err != nil || recordJSON == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordJSON, &record)
		if err != nil {
			continue
		}

		// Check department access
		err = checkDepartmentAccess(ctx, record.Department)
		if err != nil {
			continue
		}

		records = append(records, &record)
	}

	return records, nil
}

// GetRecordsByDepartment retrieves all academic records for a department (non-paginated)
func (s *SmartContract) GetRecordsByDepartment(ctx contractapi.TransactionContextInterface, department string) ([]*AcademicRecord, error) {
	department = strings.ToUpper(department)

	err := checkDepartmentAccess(ctx, department)
	if err != nil {
		return nil, err
	}

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(RecordDeptKey, []string{department})
	if err != nil {
		return nil, fmt.Errorf("failed to get records by department: %w", err)
	}
	defer resultsIterator.Close()

	records := make([]*AcademicRecord, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate records: %w", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		if len(compositeKeyParts) < 3 {
			continue
		}
		recordID := compositeKeyParts[2]

		recordJSON, err := ctx.GetStub().GetState(recordID)
		if err != nil || recordJSON == nil {
			continue
		}

		var record AcademicRecord
		err = json.Unmarshal(recordJSON, &record)
		if err != nil {
			continue
		}
		records = append(records, &record)
	}

	return records, nil
}
