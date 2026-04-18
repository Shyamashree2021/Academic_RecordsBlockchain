package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ─── Structs ─────────────────────────────────────────────────────────────────

// AIAgent is a registered agent allowed to submit oracle results
type AIAgent struct {
	AgentID      string    `json:"agentId"`
	AgentName    string    `json:"agentName"`
	AgentSecret  string    `json:"agentSecret"` // HMAC key stored on ledger
	Role         string    `json:"role"`        // "record_validator"
	IsActive     bool      `json:"isActive"`
	RegisteredBy string    `json:"registeredBy"`
	RegisteredAt time.Time `json:"registeredAt"`
}

// AIAssessment is an AI decision stored immutably on the ledger
type AIAssessment struct {
	AssessmentID   string    `json:"assessmentId"`
	RecordID       string    `json:"recordId"`
	AgentID        string    `json:"agentId"`
	Decision       string    `json:"decision"`       // APPROVE, FLAG, REJECT, NEEDS_REVIEW
	FraudScore     float64   `json:"fraudScore"`     // on-chain deterministic score
	AIScore        float64   `json:"aiScore"`        // Gemini score
	Confidence     float64   `json:"confidence"`
	Flags          []string  `json:"flags"`
	Reasoning      string    `json:"reasoning"`
	Recommendation string    `json:"recommendation"`
	Timestamp      time.Time `json:"timestamp"`
	Signature      string    `json:"signature"` // HMAC-SHA256 proof
}

// OnChainScore is the result of deterministic scoring run inside chaincode
type OnChainScore struct {
	RecordID   string    `json:"recordId"`
	FraudScore float64   `json:"fraudScore"`
	RiskLevel  string    `json:"riskLevel"` // LOW, MEDIUM, HIGH, CRITICAL
	Flags      []string  `json:"flags"`
	ScoredAt   time.Time `json:"scoredAt"`
}

// AIPolicy holds AI-generated rules stored on the ledger
type AIPolicy struct {
	PolicyID    string       `json:"policyId"`
	Version     string       `json:"version"`
	Rules       []PolicyRule `json:"rules"`
	GeneratedBy string       `json:"generatedBy"`
	CommittedBy string       `json:"committedBy,omitempty"`
	Checksum    string       `json:"checksum"` // SHA256 of rules — tamper detection
	ActiveFrom  time.Time    `json:"activeFrom,omitempty"`
}

// PolicyRule is a single deterministic rule in the AI policy
type PolicyRule struct {
	RuleID      string  `json:"ruleId"`
	Field       string  `json:"field"`    // "sgpa", "failCount", "creditsAttempted", "subjectCount"
	Operator    string  `json:"operator"` // "gt", "lt", "eq", "between"
	Value       float64 `json:"value"`
	Value2      float64 `json:"value2"` // used only with "between"
	Severity    string  `json:"severity"` // "WARN" or "BLOCK"
	Description string  `json:"description"`
}

// ─── Key Prefixes ─────────────────────────────────────────────────────────────

const (
	AIAgentPrefix      = "AIAGENT_"
	AIAssessmentPrefix = "AIASSESS_"
	AIOnChainScoreKey  = "AISCORE_"
	AIPolicyKey        = "ACTIVE_AI_POLICY"
	AIPolicyArchiveKey = "AI_POLICY_ARCHIVE_"
)

// ─── Agent Registration ───────────────────────────────────────────────────────

// RegisterAIAgent registers a trusted AI agent on the blockchain.
// Only NITWarangalMSP (admin) can call this.
func (s *SmartContract) RegisterAIAgent(ctx contractapi.TransactionContextInterface,
	agentID, agentName, agentSecret, role string) error {

	if err := checkMSPAccess(ctx, NITWarangalMSP); err != nil {
		return fmt.Errorf("only admin can register AI agents: %w", err)
	}

	key := AIAgentPrefix + agentID
	if existing, _ := ctx.GetStub().GetState(key); existing != nil {
		return fmt.Errorf("AI agent '%s' already registered", agentID)
	}

	clientID, _ := ctx.GetClientIdentity().GetID()
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()

	agent := AIAgent{
		AgentID:      agentID,
		AgentName:    agentName,
		AgentSecret:  agentSecret,
		Role:         role,
		IsActive:     true,
		RegisteredBy: clientID,
		RegisteredAt: time.Unix(txTimestamp.Seconds, 0),
	}

	agentBytes, _ := json.Marshal(agent)
	if err := ctx.GetStub().PutState(key, agentBytes); err != nil {
		return fmt.Errorf("failed to register AI agent: %w", err)
	}

	eventPayload := map[string]string{"agentId": agentID, "agentName": agentName, "role": role}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("AIAgentRegistered", eventBytes)
	return nil
}

// DeactivateAIAgent disables a registered AI agent (admin only).
func (s *SmartContract) DeactivateAIAgent(ctx contractapi.TransactionContextInterface, agentID string) error {
	if err := checkMSPAccess(ctx, NITWarangalMSP); err != nil {
		return err
	}

	key := AIAgentPrefix + agentID
	agentBytes, _ := ctx.GetStub().GetState(key)
	if agentBytes == nil {
		return fmt.Errorf("AI agent '%s' not found", agentID)
	}

	var agent AIAgent
	json.Unmarshal(agentBytes, &agent)
	agent.IsActive = false

	updated, _ := json.Marshal(agent)
	return ctx.GetStub().PutState(key, updated)
}

// ─── Oracle: Submit Signed AI Assessment ─────────────────────────────────────

// SubmitAIAssessment is called by the Node.js AI agent after Gemini analysis.
// Chaincode verifies the HMAC-SHA256 signature before storing or acting on the result.
func (s *SmartContract) SubmitAIAssessment(ctx contractapi.TransactionContextInterface,
	assessmentJSON string) error {

	if err := checkMSPAccess(ctx, NITWarangalMSP); err != nil {
		return fmt.Errorf("unauthorized oracle submission: %w", err)
	}

	var assessment AIAssessment
	if err := json.Unmarshal([]byte(assessmentJSON), &assessment); err != nil {
		return fmt.Errorf("invalid assessment JSON: %w", err)
	}

	// 1. Load the registered agent from ledger
	agentKey := AIAgentPrefix + assessment.AgentID
	agentBytes, _ := ctx.GetStub().GetState(agentKey)
	if agentBytes == nil {
		return fmt.Errorf("unregistered AI agent: '%s'", assessment.AgentID)
	}
	var agent AIAgent
	json.Unmarshal(agentBytes, &agent)

	if !agent.IsActive {
		return fmt.Errorf("AI agent '%s' is deactivated", assessment.AgentID)
	}

	// 2. Verify HMAC-SHA256 signature
	// Payload: recordId|decision|fraudScore|aiScore|unixTimestamp
	payload := fmt.Sprintf("%s|%s|%.6f|%.6f|%d",
		assessment.RecordID,
		assessment.Decision,
		assessment.FraudScore,
		assessment.AIScore,
		assessment.Timestamp.Unix(),
	)
	mac := hmac.New(sha256.New, []byte(agent.AgentSecret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if expectedSig != assessment.Signature {
		return fmt.Errorf("invalid AI agent signature — assessment rejected")
	}

	// 3. Reject stale results (older than 10 minutes)
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	currentTime := time.Unix(txTimestamp.Seconds, 0)
	if currentTime.Sub(assessment.Timestamp) > 10*time.Minute {
		return fmt.Errorf("AI assessment expired")
	}

	// 4. Verify the record exists
	recordBytes, _ := ctx.GetStub().GetState(assessment.RecordID)
	if recordBytes == nil {
		return fmt.Errorf("record '%s' not found", assessment.RecordID)
	}

	// 5. Store assessment immutably
	assessment.AssessmentID = fmt.Sprintf("%s_%s", assessment.RecordID, assessment.AgentID)
	assessBytes, _ := json.Marshal(assessment)
	if err := ctx.GetStub().PutState(AIAssessmentPrefix+assessment.AssessmentID, assessBytes); err != nil {
		return fmt.Errorf("failed to store AI assessment: %w", err)
	}

	// 6. Apply the decision to the record
	if err := s.applyAssessmentDecision(ctx, assessment, recordBytes); err != nil {
		return err
	}

	ctx.GetStub().SetEvent("AIAssessmentStored", assessBytes)
	return nil
}

// applyAssessmentDecision updates the record based on the AI decision.
func (s *SmartContract) applyAssessmentDecision(ctx contractapi.TransactionContextInterface,
	assessment AIAssessment, recordBytes []byte) error {

	var record AcademicRecord
	json.Unmarshal(recordBytes, &record)

	switch assessment.Decision {
	case "FLAG":
		// Add AI flag note — does not block the record
		record.RejectionNote = fmt.Sprintf("[AI FLAG] %s (fraud: %.2f)", assessment.Reasoning, assessment.FraudScore)
		ctx.GetStub().SetEvent("AIFlaggedRecord", recordBytes)

	case "REJECT":
		// Block the record — requires very high fraud score
		if assessment.Confidence >= 0.90 {
			record.Status = RecordRejected
			record.RejectionNote = fmt.Sprintf("[AI REJECT] %s (fraud: %.2f, confidence: %.2f)",
				assessment.Reasoning, assessment.FraudScore, assessment.Confidence)
			ctx.GetStub().SetEvent("AIRejectedRecord", recordBytes)
		}

	case "APPROVE":
		// Auto-approve only if confidence is very high AND record is SUBMITTED
		if assessment.Confidence >= 0.95 && record.Status == RecordSubmitted {
			record.Status = RecordDeptApproved
			record.ApprovedBy = "AI_AGENT_" + assessment.AgentID
			ctx.GetStub().SetEvent("AIAutoApproved", recordBytes)
		}

	case "NEEDS_REVIEW":
		// No status change — emit event for admin attention
		ctx.GetStub().SetEvent("AIRequestsHumanReview", recordBytes)
	}

	updated, _ := json.Marshal(record)
	return ctx.GetStub().PutState(record.RecordID, updated)
}

// GetAIAssessment retrieves the stored AI assessment for a record.
func (s *SmartContract) GetAIAssessment(ctx contractapi.TransactionContextInterface,
	recordID string) (*AIAssessment, error) {

	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP, VerifiersMSP); err != nil {
		return nil, err
	}

	assessID := recordID + "_RecordValidatorV1"
	assessBytes, _ := ctx.GetStub().GetState(AIAssessmentPrefix + assessID)
	if assessBytes == nil {
		return nil, fmt.Errorf("no AI assessment found for record '%s'", recordID)
	}

	var assessment AIAssessment
	json.Unmarshal(assessBytes, &assessment)
	return &assessment, nil
}

// ─── On-Chain Deterministic Scoring ──────────────────────────────────────────

// storeOnChainScoreAndNotify computes a deterministic fraud score and stores it.
// Called internally from CreateAcademicRecord — runs on all peers identically.
func (s *SmartContract) storeOnChainScoreAndNotify(ctx contractapi.TransactionContextInterface,
	recordID string, record AcademicRecord) {

	score, flags := computeOnChainScore(record)
	riskLevel := scoreToRiskLevel(score)

	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	onChainScore := OnChainScore{
		RecordID:   recordID,
		FraudScore: score,
		RiskLevel:  riskLevel,
		Flags:      flags,
		ScoredAt:   time.Unix(txTimestamp.Seconds, 0),
	}

	scoreBytes, _ := json.Marshal(onChainScore)
	ctx.GetStub().PutState(AIOnChainScoreKey+recordID, scoreBytes)

	// Emit event so Node.js AI agent wakes up and runs Gemini analysis
	aiEventPayload := map[string]interface{}{
		"recordID":   recordID,
		"studentID":  record.StudentID,
		"department": record.Department,
		"semester":   record.Semester,
		"sgpa":       record.SGPA,
		"fraudScore": score,
		"riskLevel":  riskLevel,
		"flags":      flags,
	}
	aiEventBytes, _ := json.Marshal(aiEventPayload)
	ctx.GetStub().SetEvent("AIAnalysisRequired", aiEventBytes)
}

// RunOnChainScoring is a public chaincode function to manually trigger scoring.
func (s *SmartContract) RunOnChainScoring(ctx contractapi.TransactionContextInterface,
	recordID string) (*OnChainScore, error) {

	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP); err != nil {
		return nil, err
	}

	recordBytes, _ := ctx.GetStub().GetState(recordID)
	if recordBytes == nil {
		return nil, fmt.Errorf("record '%s' not found", recordID)
	}

	var record AcademicRecord
	json.Unmarshal(recordBytes, &record)

	s.storeOnChainScoreAndNotify(ctx, recordID, record)

	// Return stored score
	scoreBytes, _ := ctx.GetStub().GetState(AIOnChainScoreKey + recordID)
	var score OnChainScore
	json.Unmarshal(scoreBytes, &score)
	return &score, nil
}

// GetOnChainScore retrieves the stored deterministic fraud score for a record.
func (s *SmartContract) GetOnChainScore(ctx contractapi.TransactionContextInterface,
	recordID string) (*OnChainScore, error) {

	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP, VerifiersMSP); err != nil {
		return nil, err
	}

	scoreBytes, _ := ctx.GetStub().GetState(AIOnChainScoreKey + recordID)
	if scoreBytes == nil {
		return nil, fmt.Errorf("no on-chain score found for record '%s'", recordID)
	}

	var score OnChainScore
	json.Unmarshal(scoreBytes, &score)
	return &score, nil
}

// computeOnChainScore runs pure deterministic anomaly detection.
// No external calls — runs identically on all peers — consensus safe.
func computeOnChainScore(record AcademicRecord) (float64, []string) {
	score := 0.0
	var flags []string

	failCount := 0
	totalGradePoints := 0.0
	gradePoints := map[string]float64{
		GradeS: 10, GradeA: 9, GradeB: 8, GradeC: 7,
		GradeD: 6, GradeP: 5, GradeU: 0, GradeR: 0,
	}

	for _, course := range record.Courses {
		if course.Grade == GradeU || course.Grade == GradeR {
			failCount++
		}
		if pts, ok := gradePoints[course.Grade]; ok {
			totalGradePoints += pts * course.Credits
		}
	}

	subjectCount := len(record.Courses)
	expectedSGPA := 0.0
	if record.TotalCredits > 0 {
		expectedSGPA = totalGradePoints / record.TotalCredits
	}

	// Rule 1: SGPA vs expected from individual grades mismatch
	if math.Abs(record.SGPA-expectedSGPA) > 1.5 {
		score += 0.35
		flags = append(flags, fmt.Sprintf("SGPA_MISMATCH: submitted=%.2f expected=%.2f", record.SGPA, expectedSGPA))
	}

	// Rule 2: Perfect SGPA with failures — statistically impossible
	if record.SGPA >= 9.5 && failCount > 0 {
		score += 0.4
		flags = append(flags, fmt.Sprintf("PERFECT_SGPA_WITH_FAILURES: sgpa=%.2f failures=%d", record.SGPA, failCount))
	}

	// Rule 3: Unusually few subjects for the credits claimed
	if subjectCount < 3 && record.TotalCredits > 18 {
		score += 0.3
		flags = append(flags, fmt.Sprintf("CREDIT_ANOMALY: %d subjects but %.0f credits", subjectCount, record.TotalCredits))
	}

	// Rule 4: Too many failures in one semester
	if failCount > 4 {
		score += 0.15
		flags = append(flags, fmt.Sprintf("HIGH_FAILURE_COUNT: %d failures", failCount))
	}

	// Rule 5: Perfect 10.0 SGPA — extremely rare, flag for verification
	if record.SGPA == 10.0 {
		score += 0.1
		flags = append(flags, "PERFECT_SCORE: SGPA=10.0 requires manual verification")
	}

	if score > 1.0 {
		score = 1.0
	}
	return score, flags
}

func scoreToRiskLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "CRITICAL"
	case score >= 0.6:
		return "HIGH"
	case score >= 0.3:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ─── AI Policy Engine ─────────────────────────────────────────────────────────

// CommitAIPolicy stores AI-generated rules on the blockchain.
// Every future CreateAcademicRecord call automatically enforces these rules.
func (s *SmartContract) CommitAIPolicy(ctx contractapi.TransactionContextInterface,
	policyJSON string) error {

	if err := checkMSPAccess(ctx, NITWarangalMSP); err != nil {
		return fmt.Errorf("only admin can commit AI policies: %w", err)
	}

	var policy AIPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return fmt.Errorf("invalid policy JSON: %w", err)
	}

	// Verify checksum for tamper detection
	rulesBytes, _ := json.Marshal(policy.Rules)
	hash := sha256.Sum256(rulesBytes)
	expectedChecksum := hex.EncodeToString(hash[:])
	if policy.Checksum != expectedChecksum {
		return fmt.Errorf("policy checksum mismatch — possible tampering detected")
	}

	// Archive old policy before replacing
	if oldPolicyBytes, _ := ctx.GetStub().GetState(AIPolicyKey); oldPolicyBytes != nil {
		txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
		archiveKey := AIPolicyArchiveKey + fmt.Sprintf("%d", txTimestamp.Seconds)
		ctx.GetStub().PutState(archiveKey, oldPolicyBytes)
	}

	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	policy.ActiveFrom = time.Unix(txTimestamp.Seconds, 0)
	clientID, _ := ctx.GetClientIdentity().GetID()
	policy.CommittedBy = clientID

	updated, _ := json.Marshal(policy)
	if err := ctx.GetStub().PutState(AIPolicyKey, updated); err != nil {
		return fmt.Errorf("failed to commit AI policy: %w", err)
	}

	ctx.GetStub().SetEvent("AIPolicyUpdated", updated)
	return nil
}

// evaluateAIPolicy checks the submitted record against active AI policy rules.
// Returns ("BLOCK", reason) if a blocking rule is violated, ("PASS", "") otherwise.
// Called internally inside CreateAcademicRecord.
func evaluateAIPolicy(ctx contractapi.TransactionContextInterface, record AcademicRecord) (string, string) {
	policyBytes, _ := ctx.GetStub().GetState(AIPolicyKey)
	if policyBytes == nil {
		return "PASS", "" // No active policy yet
	}

	var policy AIPolicy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return "PASS", "" // Corrupt policy — fail open
	}

	failCount := 0
	for _, c := range record.Courses {
		if c.Grade == GradeU || c.Grade == GradeR {
			failCount++
		}
	}

	features := map[string]float64{
		"sgpa":             record.SGPA,
		"cgpa":             record.CGPA,
		"creditsAttempted": record.TotalCredits,
		"subjectCount":     float64(len(record.Courses)),
		"failCount":        float64(failCount),
	}

	for _, rule := range policy.Rules {
		val, exists := features[rule.Field]
		if !exists {
			continue
		}

		triggered := false
		switch rule.Operator {
		case "gt":
			triggered = val > rule.Value
		case "lt":
			triggered = val < rule.Value
		case "eq":
			triggered = val == rule.Value
		case "between":
			triggered = val >= rule.Value && val <= rule.Value2
		}

		if triggered && rule.Severity == "BLOCK" {
			return "BLOCK", fmt.Sprintf("[Policy %s] %s", rule.RuleID, rule.Description)
		}
	}

	return "PASS", ""
}

// GetActiveAIPolicy returns the currently active AI policy.
func (s *SmartContract) GetActiveAIPolicy(ctx contractapi.TransactionContextInterface) (*AIPolicy, error) {
	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP); err != nil {
		return nil, err
	}

	policyBytes, _ := ctx.GetStub().GetState(AIPolicyKey)
	if policyBytes == nil {
		return nil, fmt.Errorf("no active AI policy found")
	}

	var policy AIPolicy
	json.Unmarshal(policyBytes, &policy)
	return &policy, nil
}
