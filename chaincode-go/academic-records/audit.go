package main

import (
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// getAuditTrail retrieves the full history for a given key using GetHistoryForKey
func (s *SmartContract) getAuditTrail(ctx contractapi.TransactionContextInterface, key string) ([]*AuditEntry, error) {
	historyIterator, err := ctx.GetStub().GetHistoryForKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for key %s: %w", key, err)
	}
	defer historyIterator.Close()

	entries := make([]*AuditEntry, 0)
	for historyIterator.HasNext() {
		modification, err := historyIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate history: %w", err)
		}

		entry := &AuditEntry{
			TxID:      modification.TxId,
			Timestamp: time.Unix(modification.Timestamp.Seconds, int64(modification.Timestamp.Nanos)),
			IsDelete:  modification.IsDelete,
			Value:     string(modification.Value),
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// GetStudentAuditTrail returns the full version history for a student record
func (s *SmartContract) GetStudentAuditTrail(ctx contractapi.TransactionContextInterface, rollNumber string) ([]*AuditEntry, error) {
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return nil, err
	}

	exists, err := s.StudentExists(ctx, rollNumber)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("student %s does not exist", rollNumber)
	}

	return s.getAuditTrail(ctx, rollNumber)
}

// GetRecordAuditTrail returns the full version history for an academic record
func (s *SmartContract) GetRecordAuditTrail(ctx contractapi.TransactionContextInterface, recordID string) ([]*AuditEntry, error) {
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return nil, err
	}

	exists, err := s.recordExists(ctx, recordID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("record %s does not exist", recordID)
	}

	return s.getAuditTrail(ctx, recordID)
}

// GetCertificateAuditTrail returns the full version history for a certificate
func (s *SmartContract) GetCertificateAuditTrail(ctx contractapi.TransactionContextInterface, certificateID string) ([]*AuditEntry, error) {
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return nil, err
	}

	certJSON, err := ctx.GetStub().GetState(certificateID)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}
	if certJSON == nil {
		return nil, fmt.Errorf("certificate %s does not exist", certificateID)
	}

	return s.getAuditTrail(ctx, certificateID)
}
