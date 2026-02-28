package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// GetStudentTranscript returns a complete transcript: student info + all APPROVED records + certificates
func (s *SmartContract) GetStudentTranscript(ctx contractapi.TransactionContextInterface, rollNumber string) (*StudentTranscript, error) {
	// Access Control: NITWarangalMSP, DepartmentsMSP (matching dept), or VerifiersMSP
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get client MSP ID: %v", err)
	}

	// Get student
	studentJSON, err := ctx.GetStub().GetState(rollNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to read student: %v", err)
	}
	if studentJSON == nil {
		return nil, fmt.Errorf("student %s does not exist", rollNumber)
	}

	var student Student
	err = json.Unmarshal(studentJSON, &student)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal student: %v", err)
	}

	// Access control
	if clientMSPID != NITWarangalMSP && clientMSPID != VerifiersMSP {
		if clientMSPID == DepartmentsMSP {
			err = checkDepartmentAccess(ctx, student.Department)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("unauthorized: only NITWarangalMSP, DepartmentsMSP, or VerifiersMSP can access transcripts")
		}
	}

	// Get all APPROVED records for this student
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(RecordStatusKey, []string{RecordApproved, rollNumber})
	if err != nil {
		return nil, fmt.Errorf("failed to query approved records: %w", err)
	}
	defer resultsIterator.Close()

	records := make([]*AcademicRecord, 0)
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate records: %w", err)
		}
		_, keyParts, err := ctx.GetStub().SplitCompositeKey(response.Key)
		if err != nil {
			continue
		}
		recordID := keyParts[len(keyParts)-1]

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

	// Get all certificates for this student
	certificates, err := s.GetCertificatesByStudent(ctx, rollNumber)
	if err != nil {
		certificates = []*Certificate{}
	}

	transcript := &StudentTranscript{
		Student:      &student,
		Records:      records,
		Certificates: certificates,
	}

	return transcript, nil
}

// LogVerification logs a verification event on-chain
func (s *SmartContract) LogVerification(ctx contractapi.TransactionContextInterface, certificateID, verifierInfo, purpose string) error {
	// Verify certificate exists
	certJSON, err := ctx.GetStub().GetState(certificateID)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %v", err)
	}
	if certJSON == nil {
		return fmt.Errorf("certificate %s does not exist", certificateID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	logID := fmt.Sprintf("vlog-%s-%d", certificateID, timestamp.UnixNano())

	log := VerificationLog{
		LogID:         logID,
		CertificateID: certificateID,
		VerifierMSP:   clientMSPID,
		VerifierID:    clientID,
		Timestamp:     timestamp,
		Purpose:       purpose,
	}

	logJSON, err := json.Marshal(log)
	if err != nil {
		return fmt.Errorf("failed to marshal verification log: %w", err)
	}

	err = ctx.GetStub().PutState(logID, logJSON)
	if err != nil {
		return fmt.Errorf("failed to put verification log state: %w", err)
	}

	// Composite key: verification~cert~{certificateID}~{logID}
	verKey, err := ctx.GetStub().CreateCompositeKey(VerificationCertKey, []string{certificateID, logID})
	if err != nil {
		return fmt.Errorf("failed to create verification composite key: %w", err)
	}
	err = ctx.GetStub().PutState(verKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put verification composite key: %w", err)
	}

	eventPayload := map[string]interface{}{
		"logID":         logID,
		"certificateID": certificateID,
		"verifierMSP":   clientMSPID,
		"verifierInfo":  verifierInfo,
		"purpose":       purpose,
		"timestamp":     timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("VerificationLogged", eventJSON)

	return nil
}
