/**
 * On-Chain Governance — Decentralized Policy Control
 *
 * Any of the 3 organizations (NITWarangal, Departments, Verifiers) can propose
 * a governance change. The change executes automatically when 2-of-3 orgs vote YES.
 *
 * Supported change types:
 *   SUSPEND_ISSUANCE       — Emergency: halt all certificate issuance
 *   RESUME_ISSUANCE        — Lift the suspension
 *   UPDATE_ENDORSEMENT_THRESHOLD — Change required endorsers for degree certs
 *   ADD_AUTHORIZED_VERIFIER      — Add a new MSP to the authorized verifier list
 *   REMOVE_AUTHORIZED_VERIFIER   — Remove an MSP from verifier list
 *
 * Flow:
 *   ProposeGovernanceChange → VoteOnProposal (3 orgs) → auto-executes at 2-of-3
 *   Any org can query proposals at any time via GetGovernanceProposal / GetAllGovernanceProposals
 */

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// GovernanceProposal represents a proposed change to system policy.
// Stored on-chain at key "GOV_<proposalID>"
type GovernanceProposal struct {
	ProposalID    string            `json:"proposalId"`
	ChangeType    string            `json:"changeType"`    // See constants below
	Description   string            `json:"description"`   // Human-readable explanation
	ProposedData  string            `json:"proposedData"`  // JSON payload specific to ChangeType
	ProposedBy    string            `json:"proposedBy"`    // MSP ID of proposer
	ProposedAt    time.Time         `json:"proposedAt"`
	Status        string            `json:"status"`        // PENDING, APPROVED, REJECTED, EXECUTED, EXPIRED
	Votes         map[string]string `json:"votes"`         // mspID → "YES" or "NO"
	YesCount      int               `json:"yesCount"`
	NoCount       int               `json:"noCount"`
	RequiredVotes int               `json:"requiredVotes"` // Threshold (2 of 3)
	ExecutedAt    time.Time         `json:"executedAt,omitempty"`
	ExecutedTxID  string            `json:"executedTxId,omitempty"`
}

// Governance change types
const (
	GovSuspendIssuance             = "SUSPEND_ISSUANCE"
	GovResumeIssuance              = "RESUME_ISSUANCE"
	GovUpdateEndorsementThreshold  = "UPDATE_ENDORSEMENT_THRESHOLD"
	GovAddAuthorizedVerifier       = "ADD_AUTHORIZED_VERIFIER"
	GovRemoveAuthorizedVerifier    = "REMOVE_AUTHORIZED_VERIFIER"
)

// Governance proposal statuses
const (
	GovStatusPending  = "PENDING"
	GovStatusApproved = "APPROVED"
	GovStatusRejected = "REJECTED"
	GovStatusExecuted = "EXECUTED"
)

// System state keys (govern runtime behavior of the chaincode)
const (
	govProposalPrefix      = "GOV_"
	govProposalIndexPrefix = "gov~proposal"
	SysKeyIssuanceSuspended = "SYS_ISSUANCE_SUSPENDED"
	SysKeyAuthorizedVerifiers = "SYS_AUTHORIZED_VERIFIERS"
	govRequiredVotes       = 2  // 2 of 3 orgs must approve
	govTotalOrgs           = 3
)

// issuanceSuspended checks if certificate issuance is currently suspended by governance.
// Called from IssueCertificate as a gate.
func issuanceSuspended(ctx contractapi.TransactionContextInterface) bool {
	data, err := ctx.GetStub().GetState(SysKeyIssuanceSuspended)
	if err != nil || data == nil {
		return false
	}
	return string(data) == "true"
}

// ProposeGovernanceChange creates a new governance proposal.
// Any of the 3 organizations can propose. They automatically cast a YES vote.
func (s *SmartContract) ProposeGovernanceChange(
	ctx contractapi.TransactionContextInterface,
	proposalID, changeType, description, proposedData string,
) error {
	// All 3 orgs can propose
	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP, VerifiersMSP); err != nil {
		return err
	}

	// Validate change type
	validTypes := []string{
		GovSuspendIssuance, GovResumeIssuance,
		GovUpdateEndorsementThreshold,
		GovAddAuthorizedVerifier, GovRemoveAuthorizedVerifier,
	}
	valid := false
	for _, vt := range validTypes {
		if changeType == vt {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid changeType '%s'. Valid types: %v", changeType, validTypes)
	}

	if len(proposalID) < 3 || len(proposalID) > 64 {
		return fmt.Errorf("proposalID must be 3-64 characters")
	}
	if len(description) < 10 {
		return fmt.Errorf("description must be at least 10 characters")
	}

	// Check proposal doesn't already exist
	key := govProposalPrefix + proposalID
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to check proposal existence: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("proposal %s already exists", proposalID)
	}

	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get caller MSP: %v", err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get timestamp: %v", err)
	}
	proposedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Proposer automatically votes YES
	votes := map[string]string{callerMSP: "YES"}

	proposal := GovernanceProposal{
		ProposalID:    proposalID,
		ChangeType:    changeType,
		Description:   description,
		ProposedData:  proposedData,
		ProposedBy:    callerMSP,
		ProposedAt:    proposedAt,
		Status:        GovStatusPending,
		Votes:         votes,
		YesCount:      1, // proposer's implicit YES
		NoCount:       0,
		RequiredVotes: govRequiredVotes,
	}

	proposalJSON, err := json.Marshal(proposal)
	if err != nil {
		return fmt.Errorf("failed to marshal proposal: %v", err)
	}

	if err := ctx.GetStub().PutState(key, proposalJSON); err != nil {
		return fmt.Errorf("failed to store proposal: %v", err)
	}

	// Index for listing
	indexKey, err := ctx.GetStub().CreateCompositeKey(govProposalIndexPrefix, []string{GovStatusPending, proposalID})
	if err != nil {
		return fmt.Errorf("failed to create index key: %v", err)
	}
	ctx.GetStub().PutState(indexKey, []byte{0x00})

	// Emit event
	eventData, _ := json.Marshal(map[string]string{
		"proposalId": proposalID,
		"changeType": changeType,
		"proposedBy": callerMSP,
	})
	ctx.GetStub().SetEvent("GovernanceProposed", eventData)

	return nil
}

// VoteOnProposal casts a YES or NO vote from the caller's organization.
// Each org can only vote once. Auto-executes if 2-of-3 YES votes received.
func (s *SmartContract) VoteOnProposal(
	ctx contractapi.TransactionContextInterface,
	proposalID, vote string,
) error {
	// All 3 orgs can vote
	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP, VerifiersMSP); err != nil {
		return err
	}

	if vote != "YES" && vote != "NO" {
		return fmt.Errorf("vote must be 'YES' or 'NO'")
	}

	callerMSP, _ := ctx.GetClientIdentity().GetMSPID()

	// Load proposal
	key := govProposalPrefix + proposalID
	proposalJSON, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to read proposal: %v", err)
	}
	if proposalJSON == nil {
		return fmt.Errorf("proposal %s not found", proposalID)
	}

	var proposal GovernanceProposal
	if err := json.Unmarshal(proposalJSON, &proposal); err != nil {
		return fmt.Errorf("failed to unmarshal proposal: %v", err)
	}

	// Only PENDING proposals can be voted on
	if proposal.Status != GovStatusPending {
		return fmt.Errorf("proposal %s is already %s — voting is closed", proposalID, proposal.Status)
	}

	// Check if org already voted
	if existingVote, alreadyVoted := proposal.Votes[callerMSP]; alreadyVoted {
		return fmt.Errorf("organization %s already voted %s on proposal %s", callerMSP, existingVote, proposalID)
	}

	// Record vote
	proposal.Votes[callerMSP] = vote
	if vote == "YES" {
		proposal.YesCount++
	} else {
		proposal.NoCount++
	}

	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	now := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Check if approval threshold reached (2 of 3)
	if proposal.YesCount >= govRequiredVotes {
		proposal.Status = GovStatusApproved

		// Execute the change immediately
		execErr := executeGovernanceChange(ctx, &proposal)
		if execErr != nil {
			// Mark as approved but not executed — manual intervention needed
			proposal.ExecutedTxID = "EXEC_FAILED: " + execErr.Error()
		} else {
			proposal.Status = GovStatusExecuted
			proposal.ExecutedAt = now
			proposal.ExecutedTxID = ctx.GetStub().GetTxID()
		}
	} else if proposal.NoCount > govTotalOrgs-govRequiredVotes {
		// Enough NO votes that approval is impossible
		proposal.Status = GovStatusRejected
	}

	// Update index if status changed from PENDING
	if proposal.Status != GovStatusPending {
		oldIndexKey, _ := ctx.GetStub().CreateCompositeKey(govProposalIndexPrefix, []string{GovStatusPending, proposalID})
		ctx.GetStub().DelState(oldIndexKey)
		newIndexKey, _ := ctx.GetStub().CreateCompositeKey(govProposalIndexPrefix, []string{proposal.Status, proposalID})
		ctx.GetStub().PutState(newIndexKey, []byte{0x00})
	}

	updatedJSON, err := json.Marshal(proposal)
	if err != nil {
		return fmt.Errorf("failed to marshal updated proposal: %v", err)
	}
	if err := ctx.GetStub().PutState(key, updatedJSON); err != nil {
		return fmt.Errorf("failed to update proposal: %v", err)
	}

	// Emit event
	eventData, _ := json.Marshal(map[string]interface{}{
		"proposalId": proposalID,
		"voter":      callerMSP,
		"vote":       vote,
		"yesCount":   proposal.YesCount,
		"status":     proposal.Status,
	})
	ctx.GetStub().SetEvent("GovernanceVoteCast", eventData)

	return nil
}

// executeGovernanceChange applies the actual system change when a proposal is approved.
func executeGovernanceChange(ctx contractapi.TransactionContextInterface, proposal *GovernanceProposal) error {
	switch proposal.ChangeType {

	case GovSuspendIssuance:
		// Set system flag — IssueCertificate checks this before proceeding
		return ctx.GetStub().PutState(SysKeyIssuanceSuspended, []byte("true"))

	case GovResumeIssuance:
		return ctx.GetStub().DelState(SysKeyIssuanceSuspended)

	case GovAddAuthorizedVerifier:
		// proposedData = MSP ID to add
		if len(proposal.ProposedData) == 0 {
			return fmt.Errorf("proposedData must contain the MSP ID to add")
		}
		return addAuthorizedVerifier(ctx, proposal.ProposedData)

	case GovRemoveAuthorizedVerifier:
		if len(proposal.ProposedData) == 0 {
			return fmt.Errorf("proposedData must contain the MSP ID to remove")
		}
		return removeAuthorizedVerifier(ctx, proposal.ProposedData)

	case GovUpdateEndorsementThreshold:
		// proposedData = JSON: {"threshold": 2, "description": "..."}
		// Store new threshold in system state
		return ctx.GetStub().PutState("SYS_ENDORSEMENT_THRESHOLD", []byte(proposal.ProposedData))

	default:
		return fmt.Errorf("unknown changeType: %s", proposal.ChangeType)
	}
}

// addAuthorizedVerifier adds an MSP to the authorized verifier list.
func addAuthorizedVerifier(ctx contractapi.TransactionContextInterface, mspID string) error {
	verifiers := loadAuthorizedVerifiers(ctx)
	for _, v := range verifiers {
		if v == mspID {
			return nil // already exists
		}
	}
	verifiers = append(verifiers, mspID)
	data, _ := json.Marshal(verifiers)
	return ctx.GetStub().PutState(SysKeyAuthorizedVerifiers, data)
}

// removeAuthorizedVerifier removes an MSP from the authorized verifier list.
func removeAuthorizedVerifier(ctx contractapi.TransactionContextInterface, mspID string) error {
	verifiers := loadAuthorizedVerifiers(ctx)
	updated := make([]string, 0, len(verifiers))
	for _, v := range verifiers {
		if v != mspID {
			updated = append(updated, v)
		}
	}
	data, _ := json.Marshal(updated)
	return ctx.GetStub().PutState(SysKeyAuthorizedVerifiers, data)
}

// loadAuthorizedVerifiers reads the current authorized verifier list from state.
func loadAuthorizedVerifiers(ctx contractapi.TransactionContextInterface) []string {
	data, err := ctx.GetStub().GetState(SysKeyAuthorizedVerifiers)
	if err != nil || data == nil {
		// Default: VerifiersMSP is always authorized
		return []string{VerifiersMSP}
	}
	var verifiers []string
	_ = json.Unmarshal(data, &verifiers)
	return verifiers
}

// GetGovernanceProposal returns a single governance proposal by ID.
func (s *SmartContract) GetGovernanceProposal(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
) (*GovernanceProposal, error) {
	key := govProposalPrefix + proposalID
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read proposal: %v", err)
	}
	if data == nil {
		return nil, fmt.Errorf("proposal %s not found", proposalID)
	}

	var proposal GovernanceProposal
	if err := json.Unmarshal(data, &proposal); err != nil {
		return nil, err
	}
	return &proposal, nil
}

// GetAllGovernanceProposals returns all proposals, optionally filtered by status.
// statusFilter: "PENDING", "EXECUTED", "REJECTED", or "" for all.
func (s *SmartContract) GetAllGovernanceProposals(
	ctx contractapi.TransactionContextInterface,
	statusFilter string,
) ([]*GovernanceProposal, error) {
	// If filtering by status, use the composite key index
	if statusFilter != "" {
		return getProposalsByStatus(ctx, statusFilter)
	}

	// Otherwise scan all GOV_ keys
	resultsIterator, err := ctx.GetStub().GetStateByRange(govProposalPrefix, govProposalPrefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to query proposals: %v", err)
	}
	defer resultsIterator.Close()

	proposals := make([]*GovernanceProposal, 0)
	for resultsIterator.HasNext() {
		result, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var proposal GovernanceProposal
		if err := json.Unmarshal(result.Value, &proposal); err != nil {
			continue
		}
		proposals = append(proposals, &proposal)
	}
	return proposals, nil
}

func getProposalsByStatus(ctx contractapi.TransactionContextInterface, status string) ([]*GovernanceProposal, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(govProposalIndexPrefix, []string{status})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	proposals := make([]*GovernanceProposal, 0)
	for iter.HasNext() {
		result, err := iter.Next()
		if err != nil {
			return nil, err
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(result.Key)
		if err != nil || len(parts) < 2 {
			continue
		}
		proposalID := parts[1]
		proposal, err := getProposalByID(ctx, proposalID)
		if err != nil {
			continue
		}
		proposals = append(proposals, proposal)
	}
	return proposals, nil
}

func getProposalByID(ctx contractapi.TransactionContextInterface, proposalID string) (*GovernanceProposal, error) {
	data, err := ctx.GetStub().GetState(govProposalPrefix + proposalID)
	if err != nil || data == nil {
		return nil, fmt.Errorf("proposal %s not found", proposalID)
	}
	var p GovernanceProposal
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetSystemState returns current governance-controlled system state (for auditing).
func (s *SmartContract) GetSystemState(
	ctx contractapi.TransactionContextInterface,
) (map[string]interface{}, error) {
	state := map[string]interface{}{
		"issuanceSuspended":    issuanceSuspended(ctx),
		"authorizedVerifiers":  loadAuthorizedVerifiers(ctx),
	}

	// Check endorsement threshold
	thresholdData, _ := ctx.GetStub().GetState("SYS_ENDORSEMENT_THRESHOLD")
	if thresholdData != nil {
		state["endorsementThreshold"] = string(thresholdData)
	} else {
		state["endorsementThreshold"] = `{"threshold":2,"description":"Default: NITWarangal + Departments"}`
	}

	return state, nil
}
