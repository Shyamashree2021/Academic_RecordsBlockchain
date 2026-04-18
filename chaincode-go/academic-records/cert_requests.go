package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// RequestCertificate creates a new certificate request (any MSP can call — student accessible)
func (s *SmartContract) RequestCertificate(ctx contractapi.TransactionContextInterface,
	requestID, studentID, certType, reason string) error {

	err := validateCertificateType(certType)
	if err != nil {
		return err
	}

	if len(reason) < 5 {
		return fmt.Errorf("reason must be at least 5 characters")
	}

	exists, err := s.StudentExists(ctx, studentID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("student %s does not exist", studentID)
	}

	existingJSON, err := ctx.GetStub().GetState(requestID)
	if err != nil {
		return fmt.Errorf("failed to check request existence: %v", err)
	}
	if existingJSON != nil {
		return fmt.Errorf("certificate request %s already exists", requestID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	request := CertificateRequest{
		RequestID:       requestID,
		StudentID:       studentID,
		CertificateType: certType,
		Reason:          reason,
		Status:          CertReqRequested,
		RequestedAt:     timestamp,
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate request: %w", err)
	}

	err = ctx.GetStub().PutState(requestID, requestJSON)
	if err != nil {
		return fmt.Errorf("failed to put certificate request state: %w", err)
	}

	// Composite key: certreq~student~{studentID}~{requestID}
	studentKey, err := ctx.GetStub().CreateCompositeKey(CertReqStudentKey, []string{studentID, requestID})
	if err != nil {
		return fmt.Errorf("failed to create student composite key: %w", err)
	}
	err = ctx.GetStub().PutState(studentKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put student composite key: %w", err)
	}

	// Composite key: certreq~status~{status}~{requestID}
	statusKey, err := ctx.GetStub().CreateCompositeKey(CertReqStatusKey, []string{CertReqRequested, requestID})
	if err != nil {
		return fmt.Errorf("failed to create status composite key: %w", err)
	}
	err = ctx.GetStub().PutState(statusKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put status composite key: %w", err)
	}

	eventPayload := map[string]interface{}{
		"requestID":       requestID,
		"studentID":       studentID,
		"certificateType": certType,
		"requestedAt":     timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateRequested", eventJSON)

	return nil
}

// RecommendCertificateRequest moves a REQUESTED certificate request to RECOMMENDED
func (s *SmartContract) RecommendCertificateRequest(ctx contractapi.TransactionContextInterface, requestID string) error {
	err := checkMSPAccess(ctx, DepartmentsMSP, NITWarangalMSP)
	if err != nil {
		return err
	}

	requestJSON, err := ctx.GetStub().GetState(requestID)
	if err != nil {
		return fmt.Errorf("failed to read certificate request: %v", err)
	}
	if requestJSON == nil {
		return fmt.Errorf("certificate request %s does not exist", requestID)
	}

	var request CertificateRequest
	err = json.Unmarshal(requestJSON, &request)
	if err != nil {
		return fmt.Errorf("failed to unmarshal certificate request: %v", err)
	}

	if request.Status != CertReqRequested {
		return fmt.Errorf("can only recommend requests with REQUESTED status; current status is '%s'", request.Status)
	}

	// Update status composite keys
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(CertReqStatusKey, []string{CertReqRequested, requestID})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	newStatusKey, err := ctx.GetStub().CreateCompositeKey(CertReqStatusKey, []string{CertReqRecommended, requestID})
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

	request.Status = CertReqRecommended
	request.RecommendedBy = clientID
	request.RecommendedAt = timestamp

	updatedJSON, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	err = ctx.GetStub().PutState(requestID, updatedJSON)
	if err != nil {
		return fmt.Errorf("failed to put request state: %w", err)
	}

	eventPayload := map[string]interface{}{
		"requestID":     requestID,
		"studentID":     request.StudentID,
		"recommendedBy": clientID,
		"timestamp":     timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateRequestRecommended", eventJSON)

	return nil
}

// ApproveCertificateRequest moves a RECOMMENDED certificate request to APPROVED
func (s *SmartContract) ApproveCertificateRequest(ctx contractapi.TransactionContextInterface, requestID string) error {
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return err
	}

	requestJSON, err := ctx.GetStub().GetState(requestID)
	if err != nil {
		return fmt.Errorf("failed to read certificate request: %v", err)
	}
	if requestJSON == nil {
		return fmt.Errorf("certificate request %s does not exist", requestID)
	}

	var request CertificateRequest
	err = json.Unmarshal(requestJSON, &request)
	if err != nil {
		return fmt.Errorf("failed to unmarshal certificate request: %v", err)
	}

	if request.Status != CertReqRecommended {
		return fmt.Errorf("can only approve requests with RECOMMENDED status; current status is '%s'", request.Status)
	}

	// Update status composite keys
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(CertReqStatusKey, []string{CertReqRecommended, requestID})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	newStatusKey, err := ctx.GetStub().CreateCompositeKey(CertReqStatusKey, []string{CertReqApproved, requestID})
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

	request.Status = CertReqApproved
	request.ApprovedBy = clientID
	request.ApprovedAt = timestamp

	updatedJSON, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	err = ctx.GetStub().PutState(requestID, updatedJSON)
	if err != nil {
		return fmt.Errorf("failed to put request state: %w", err)
	}

	eventPayload := map[string]interface{}{
		"requestID":  requestID,
		"studentID":  request.StudentID,
		"approvedBy": clientID,
		"timestamp":  timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateRequestApproved", eventJSON)

	return nil
}

// RejectCertificateRequest rejects a certificate request with a reason
func (s *SmartContract) RejectCertificateRequest(ctx contractapi.TransactionContextInterface, requestID, reason string) error {
	err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP)
	if err != nil {
		return err
	}

	if len(reason) < 10 {
		return fmt.Errorf("rejection reason must be at least 10 characters")
	}

	requestJSON, err := ctx.GetStub().GetState(requestID)
	if err != nil {
		return fmt.Errorf("failed to read certificate request: %v", err)
	}
	if requestJSON == nil {
		return fmt.Errorf("certificate request %s does not exist", requestID)
	}

	var request CertificateRequest
	err = json.Unmarshal(requestJSON, &request)
	if err != nil {
		return fmt.Errorf("failed to unmarshal certificate request: %v", err)
	}

	if request.Status == CertReqApproved || request.Status == CertReqIssued {
		return fmt.Errorf("cannot reject a request that is already %s", request.Status)
	}
	if request.Status == CertReqRejected {
		return fmt.Errorf("request is already rejected")
	}

	oldStatus := request.Status

	// Update status composite keys
	oldStatusKey, err := ctx.GetStub().CreateCompositeKey(CertReqStatusKey, []string{oldStatus, requestID})
	if err == nil {
		ctx.GetStub().DelState(oldStatusKey)
	}

	newStatusKey, err := ctx.GetStub().CreateCompositeKey(CertReqStatusKey, []string{CertReqRejected, requestID})
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

	request.Status = CertReqRejected
	request.RejectedBy = clientID
	request.RejectedAt = timestamp
	request.RejectionReason = reason

	updatedJSON, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	err = ctx.GetStub().PutState(requestID, updatedJSON)
	if err != nil {
		return fmt.Errorf("failed to put request state: %w", err)
	}

	eventPayload := map[string]interface{}{
		"requestID":  requestID,
		"studentID":  request.StudentID,
		"reason":     reason,
		"rejectedBy": clientID,
		"timestamp":  timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateRequestRejected", eventJSON)

	return nil
}

// GetCertificateRequest retrieves a certificate request by ID
func (s *SmartContract) GetCertificateRequest(ctx contractapi.TransactionContextInterface, requestID string) (*CertificateRequest, error) {
	requestJSON, err := ctx.GetStub().GetState(requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate request: %v", err)
	}
	if requestJSON == nil {
		return nil, fmt.Errorf("certificate request %s does not exist", requestID)
	}

	var request CertificateRequest
	err = json.Unmarshal(requestJSON, &request)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate request: %v", err)
	}

	return &request, nil
}

// GetCertificateRequestsByStudent retrieves all certificate requests for a student
func (s *SmartContract) GetCertificateRequestsByStudent(ctx contractapi.TransactionContextInterface, studentID string) ([]*CertificateRequest, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(CertReqStudentKey, []string{studentID})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate requests by student: %w", err)
	}
	defer resultsIterator.Close()

	requests := make([]*CertificateRequest, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate requests: %w", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}
		if len(compositeKeyParts) < 2 {
			continue
		}
		requestID := compositeKeyParts[1]

		requestJSON, err := ctx.GetStub().GetState(requestID)
		if err != nil || requestJSON == nil {
			continue
		}

		var request CertificateRequest
		err = json.Unmarshal(requestJSON, &request)
		if err != nil {
			continue
		}
		requests = append(requests, &request)
	}

	return requests, nil
}

// GetPendingCertificateRequests retrieves pending certificate requests with pagination
func (s *SmartContract) GetPendingCertificateRequests(ctx contractapi.TransactionContextInterface, bookmark string, pageSize int) (*PaginatedQueryResult, error) {
	err := checkMSPAccess(ctx, NITWarangalMSP)
	if err != nil {
		return nil, err
	}

	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	allRequests := make([]*CertificateRequest, 0)

	// Get REQUESTED
	requestedIterator, _, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(
		CertReqStatusKey, []string{CertReqRequested}, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query requested certificate requests: %v", err)
	}
	defer requestedIterator.Close()

	for requestedIterator.HasNext() {
		queryResponse, err := requestedIterator.Next()
		if err != nil {
			continue
		}
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 2 {
			continue
		}
		requestID := compositeKeyParts[1]
		requestJSON, err := ctx.GetStub().GetState(requestID)
		if err != nil || requestJSON == nil {
			continue
		}
		var request CertificateRequest
		err = json.Unmarshal(requestJSON, &request)
		if err != nil {
			continue
		}
		allRequests = append(allRequests, &request)
	}

	// Get RECOMMENDED
	recommendedIterator, responseMetadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(
		CertReqStatusKey, []string{CertReqRecommended}, int32(pageSize), "")
	if err != nil {
		return nil, fmt.Errorf("failed to query recommended certificate requests: %v", err)
	}
	defer recommendedIterator.Close()

	for recommendedIterator.HasNext() {
		queryResponse, err := recommendedIterator.Next()
		if err != nil {
			continue
		}
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 2 {
			continue
		}
		requestID := compositeKeyParts[1]
		requestJSON, err := ctx.GetStub().GetState(requestID)
		if err != nil || requestJSON == nil {
			continue
		}
		var request CertificateRequest
		err = json.Unmarshal(requestJSON, &request)
		if err != nil {
			continue
		}
		allRequests = append(allRequests, &request)
	}

	result := &PaginatedQueryResult{
		Records:     allRequests,
		Bookmark:    responseMetadata.Bookmark,
		RecordCount: len(allRequests),
		HasMore:     responseMetadata.Bookmark != "",
	}

	return result, nil
}
