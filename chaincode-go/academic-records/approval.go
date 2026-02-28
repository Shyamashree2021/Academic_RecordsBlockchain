package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SubmitAcademicRecord moves a DRAFT record to SUBMITTED status
func (s *SmartContract) SubmitAcademicRecord(ctx contractapi.TransactionContextInterface, recordID string) error {
	err := checkMSPAccess(ctx, DepartmentsMSP, NITWarangalMSP)
	if err != nil {
		return err
	}

	record, err := s.GetAcademicRecord(ctx, recordID)
	if err != nil {
		return err
	}

	if record.Status != RecordDraft {
		return fmt.Errorf("can only submit records with DRAFT status; current status is '%s'", record.Status)
	}

	// If DepartmentsMSP, verify department matches
	clientMSPID, _ := ctx.GetClientIdentity().GetMSPID()
	if clientMSPID == DepartmentsMSP {
		err = checkClientAttribute(ctx, "department", record.Department)
		if err != nil {
			return fmt.Errorf("department mismatch: %w", err)
		}
	}

	// Update status composite key
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordDraft, record.StudentID, recordID})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	newStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordSubmitted, record.StudentID, recordID})
	if err != nil {
		return fmt.Errorf("failed to create new status key: %w", err)
	}
	err = ctx.GetStub().PutState(newStatusKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put new status key: %w", err)
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

	record.Status = RecordSubmitted
	record.SubmittedBy = clientID
	record.Timestamp = timestamp

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	err = ctx.GetStub().PutState(recordID, recordJSON)
	if err != nil {
		return fmt.Errorf("failed to put record state: %w", err)
	}

	eventPayload := map[string]interface{}{
		"recordID":    recordID,
		"studentID":   record.StudentID,
		"department":  record.Department,
		"submittedBy": clientID,
		"timestamp":   timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RecordSubmitted", eventJSON)

	return nil
}

// DeptApproveAcademicRecord moves a SUBMITTED record to DEPT_APPROVED (department-level approval)
func (s *SmartContract) DeptApproveAcademicRecord(ctx contractapi.TransactionContextInterface, recordID string) error {
	err := checkMSPAccess(ctx, DepartmentsMSP)
	if err != nil {
		return err
	}

	record, err := s.GetAcademicRecord(ctx, recordID)
	if err != nil {
		return err
	}

	if record.Status != RecordSubmitted {
		return fmt.Errorf("can only department-approve records with SUBMITTED status; current status is '%s'", record.Status)
	}

	// Verify department user belongs to same department as the record
	err = checkClientAttribute(ctx, "department", record.Department)
	if err != nil {
		return fmt.Errorf("department mismatch for approval: %w", err)
	}

	// Update status composite keys
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordSubmitted, record.StudentID, recordID})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	newStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordDeptApproved, record.StudentID, recordID})
	if err != nil {
		return fmt.Errorf("failed to create new status key: %w", err)
	}
	err = ctx.GetStub().PutState(newStatusKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put new status key: %w", err)
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

	record.Status = RecordDeptApproved
	record.Timestamp = timestamp

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	err = ctx.GetStub().PutState(recordID, recordJSON)
	if err != nil {
		return fmt.Errorf("failed to put record state: %w", err)
	}

	eventPayload := map[string]interface{}{
		"recordID":       recordID,
		"studentID":      record.StudentID,
		"department":     record.Department,
		"deptApprovedBy": clientID,
		"timestamp":      timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RecordDeptApproved", eventJSON)

	return nil
}

// RejectAcademicRecord moves any non-APPROVED record to REJECTED status with a reason
func (s *SmartContract) RejectAcademicRecord(ctx contractapi.TransactionContextInterface, recordID, reason string) error {
	err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP)
	if err != nil {
		return err
	}

	if len(reason) < 10 {
		return fmt.Errorf("rejection reason must be at least 10 characters")
	}

	record, err := s.GetAcademicRecord(ctx, recordID)
	if err != nil {
		return err
	}

	if record.Status == RecordApproved {
		return fmt.Errorf("cannot reject an already approved record")
	}
	if record.Status == RecordRejected {
		return fmt.Errorf("record is already rejected")
	}

	// If DepartmentsMSP, verify department matches
	clientMSPID, _ := ctx.GetClientIdentity().GetMSPID()
	if clientMSPID == DepartmentsMSP {
		err = checkClientAttribute(ctx, "department", record.Department)
		if err != nil {
			return fmt.Errorf("department mismatch: %w", err)
		}
	}

	oldStatus := record.Status

	// Update status composite keys
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{oldStatus, record.StudentID, recordID})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	newStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordRejected, record.StudentID, recordID})
	if err != nil {
		return fmt.Errorf("failed to create new status key: %w", err)
	}
	err = ctx.GetStub().PutState(newStatusKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put new status key: %w", err)
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

	record.Status = RecordRejected
	record.RejectionNote = reason
	record.Timestamp = timestamp

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	err = ctx.GetStub().PutState(recordID, recordJSON)
	if err != nil {
		return fmt.Errorf("failed to put record state: %w", err)
	}

	eventPayload := map[string]interface{}{
		"recordID":   recordID,
		"studentID":  record.StudentID,
		"department": record.Department,
		"oldStatus":  oldStatus,
		"reason":     reason,
		"rejectedBy": clientID,
		"timestamp":  timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RecordRejected", eventJSON)

	return nil
}

// ResubmitAcademicRecord moves a REJECTED record back to SUBMITTED for re-review
func (s *SmartContract) ResubmitAcademicRecord(ctx contractapi.TransactionContextInterface, recordID string) error {
	err := checkMSPAccess(ctx, DepartmentsMSP, NITWarangalMSP)
	if err != nil {
		return err
	}

	record, err := s.GetAcademicRecord(ctx, recordID)
	if err != nil {
		return err
	}

	if record.Status != RecordRejected {
		return fmt.Errorf("can only resubmit records with REJECTED status; current status is '%s'", record.Status)
	}

	// If DepartmentsMSP, verify department matches
	clientMSPID, _ := ctx.GetClientIdentity().GetMSPID()
	if clientMSPID == DepartmentsMSP {
		err = checkClientAttribute(ctx, "department", record.Department)
		if err != nil {
			return fmt.Errorf("department mismatch: %w", err)
		}
	}

	// Update status composite keys
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordRejected, record.StudentID, recordID})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	newStatusKey, err := ctx.GetStub().CreateCompositeKey(RecordStatusKey, []string{RecordSubmitted, record.StudentID, recordID})
	if err != nil {
		return fmt.Errorf("failed to create new status key: %w", err)
	}
	err = ctx.GetStub().PutState(newStatusKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put new status key: %w", err)
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

	record.Status = RecordSubmitted
	record.RejectionNote = "" // Clear rejection note on resubmission
	record.Timestamp = timestamp
	record.SubmittedBy = clientID

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	err = ctx.GetStub().PutState(recordID, recordJSON)
	if err != nil {
		return fmt.Errorf("failed to put record state: %w", err)
	}

	eventPayload := map[string]interface{}{
		"recordID":      recordID,
		"studentID":     record.StudentID,
		"department":    record.Department,
		"resubmittedBy": clientID,
		"timestamp":     timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RecordResubmitted", eventJSON)

	return nil
}
