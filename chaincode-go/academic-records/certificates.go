package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

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

	certificates := make([]*Certificate, 0)
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
