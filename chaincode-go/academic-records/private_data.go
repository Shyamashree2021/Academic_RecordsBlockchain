/**
 * Private Data Collections (PDC) — Sensitive Academic Data
 *
 * Architecture:
 *   Public ledger  → course letter grades (S/A/B/C/D), SGPA, CGPA  (visible to all)
 *   sensitiveAcademicCollection → numerical marks per course         (NITWarangal + Departments only)
 *
 * Hash-on-chain pattern:
 *   When detailed marks are stored, their SHA256 hash is written to the
 *   public ledger so ANYONE can verify the private data hasn't been tampered with,
 *   even though they cannot read the actual marks.
 *
 * Collections:
 *   studentPrivateCollection      → OR(NITWarangalMSP.member)               personal info
 *   sensitiveAcademicCollection   → OR(NITWarangalMSP.member, DepartmentsMSP.member)  grade marks
 */

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const sensitiveAcademicCollection = "sensitiveAcademicCollection"

// CourseMark holds the numerical breakdown for a single course.
// Stored only in the private collection — never on the public ledger.
type CourseMark struct {
	CourseCode    string  `json:"courseCode"`
	InternalMarks float64 `json:"internalMarks"` // Out of 40
	ExternalMarks float64 `json:"externalMarks"` // Out of 60
	TotalMarks    float64 `json:"totalMarks"`    // Out of 100
	GradePoints   float64 `json:"gradePoints"`   // 10-point scale
}

// SensitiveGradeRecord is the full private record for one semester.
// Key in private collection: "SGR_<recordID>"
type SensitiveGradeRecord struct {
	RecordID    string       `json:"recordId"`
	StudentID   string       `json:"studentId"`
	Semester    int          `json:"semester"`
	CourseMarks []CourseMark `json:"courseMarks"`
	StoredBy    string       `json:"storedBy"` // MSP who stored it
}

// GradeReportHash is stored on the PUBLIC ledger as proof of private data.
// Key: "GRH_<recordID>"
type GradeReportHash struct {
	RecordID string `json:"recordId"`
	Hash     string `json:"hash"`    // SHA256 of the JSON-serialized SensitiveGradeRecord
	StoredAt string `json:"storedAt"` // Block timestamp
}

const gradeReportHashPrefix = "GRH_"

// StorePrivateMarks stores detailed numerical marks in the private collection.
// Called by NITWarangalMSP or DepartmentsMSP after a record is submitted.
// Input: courseMarksJSON — JSON array of CourseMark objects (passed via transient data "courseMarks")
func (s *SmartContract) StorePrivateMarks(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) error {
	// Only NITWarangal or Departments can store private marks
	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP); err != nil {
		return err
	}

	// Verify the public record exists
	exists, err := s.recordExists(ctx, recordID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("academic record %s does not exist on the public ledger", recordID)
	}

	// Read courseMarks from transient data (never logged on-chain as-is)
	transientMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("failed to get transient data: %v", err)
	}
	courseMarksBytes, ok := transientMap["courseMarks"]
	if !ok {
		return fmt.Errorf("courseMarks must be provided in transient data")
	}

	var courseMarks []CourseMark
	if err := json.Unmarshal(courseMarksBytes, &courseMarks); err != nil {
		return fmt.Errorf("invalid courseMarks JSON: %v", err)
	}
	if len(courseMarks) == 0 {
		return fmt.Errorf("courseMarks cannot be empty")
	}

	// Validate marks
	for i, cm := range courseMarks {
		if cm.InternalMarks < 0 || cm.InternalMarks > 40 {
			return fmt.Errorf("course %d (%s): internal marks %.1f out of range (0-40)", i+1, cm.CourseCode, cm.InternalMarks)
		}
		if cm.ExternalMarks < 0 || cm.ExternalMarks > 60 {
			return fmt.Errorf("course %d (%s): external marks %.1f out of range (0-60)", i+1, cm.CourseCode, cm.ExternalMarks)
		}
		courseMarks[i].TotalMarks = cm.InternalMarks + cm.ExternalMarks
		if cm.GradePoints < 0 || cm.GradePoints > 10 {
			return fmt.Errorf("course %d (%s): grade points %.1f out of range (0-10)", i+1, cm.CourseCode, cm.GradePoints)
		}
	}

	clientID, _ := ctx.GetClientIdentity().GetID()
	mspID, _ := ctx.GetClientIdentity().GetMSPID()

	// Get public record to extract studentID and semester
	recordJSON, _ := ctx.GetStub().GetState(recordID)
	var record AcademicRecord
	_ = json.Unmarshal(recordJSON, &record)

	sensitiveRecord := SensitiveGradeRecord{
		RecordID:    recordID,
		StudentID:   record.StudentID,
		Semester:    record.Semester,
		CourseMarks: courseMarks,
		StoredBy:    mspID + ":" + clientID,
	}

	sensitiveJSON, err := json.Marshal(sensitiveRecord)
	if err != nil {
		return fmt.Errorf("failed to marshal sensitive record: %v", err)
	}

	// Store in private collection
	privateKey := "SGR_" + recordID
	if err := ctx.GetStub().PutPrivateData(sensitiveAcademicCollection, privateKey, sensitiveJSON); err != nil {
		return fmt.Errorf("failed to store private marks: %v", err)
	}

	// Compute SHA256 hash of private data and store on PUBLIC ledger
	// This lets anyone verify the private data hasn't changed, even without access
	hash := sha256.Sum256(sensitiveJSON)
	hashHex := fmt.Sprintf("%x", hash)

	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()

	gradeHash := GradeReportHash{
		RecordID: recordID,
		Hash:     hashHex,
		StoredAt: fmt.Sprintf("%d", txTimestamp.Seconds),
	}
	gradeHashJSON, _ := json.Marshal(gradeHash)
	publicKey := gradeReportHashPrefix + recordID
	if err := ctx.GetStub().PutState(publicKey, gradeHashJSON); err != nil {
		return fmt.Errorf("failed to store grade hash on public ledger: %v", err)
	}

	// Emit event (no sensitive data in event)
	ctx.GetStub().SetEvent("PrivateMarksStored", []byte(`{"recordId":"`+recordID+`","hash":"`+hashHex+`"}`))

	return nil
}

// GetPrivateMarks retrieves detailed marks from the private collection.
// Only NITWarangalMSP and DepartmentsMSP peers can call this.
func (s *SmartContract) GetPrivateMarks(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (*SensitiveGradeRecord, error) {
	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP); err != nil {
		return nil, err
	}

	privateKey := "SGR_" + recordID
	data, err := ctx.GetStub().GetPrivateData(sensitiveAcademicCollection, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read private marks: %v", err)
	}
	if data == nil {
		return nil, fmt.Errorf("no private marks found for record %s", recordID)
	}

	var record SensitiveGradeRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// GetGradeReportHash returns the public SHA256 hash of the private marks.
// Anyone can call this to verify the integrity of private data.
func (s *SmartContract) GetGradeReportHash(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (*GradeReportHash, error) {
	publicKey := gradeReportHashPrefix + recordID
	data, err := ctx.GetStub().GetState(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read grade hash: %v", err)
	}
	if data == nil {
		return nil, fmt.Errorf("no grade hash found for record %s — private marks not stored yet", recordID)
	}

	var gh GradeReportHash
	if err := json.Unmarshal(data, &gh); err != nil {
		return nil, err
	}
	return &gh, nil
}

// VerifyPrivateMarksIntegrity lets an authorized org verify that the private marks
// they hold match the public hash — proves data hasn't been tampered with.
func (s *SmartContract) VerifyPrivateMarksIntegrity(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (bool, error) {
	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP); err != nil {
		return false, err
	}

	// Get private data
	privateKey := "SGR_" + recordID
	privateData, err := ctx.GetStub().GetPrivateData(sensitiveAcademicCollection, privateKey)
	if err != nil || privateData == nil {
		return false, fmt.Errorf("private marks not found for record %s", recordID)
	}

	// Recompute hash
	recomputedHash := sha256.Sum256(privateData)
	recomputedHashHex := fmt.Sprintf("%x", recomputedHash)

	// Get public hash
	publicKey := gradeReportHashPrefix + recordID
	publicData, err := ctx.GetStub().GetState(publicKey)
	if err != nil || publicData == nil {
		return false, fmt.Errorf("public hash not found for record %s", recordID)
	}

	var gh GradeReportHash
	if err := json.Unmarshal(publicData, &gh); err != nil {
		return false, err
	}

	// Compare
	if recomputedHashHex != gh.Hash {
		return false, fmt.Errorf("INTEGRITY VIOLATION: hash mismatch for record %s — private data may have been tampered", recordID)
	}
	return true, nil
}
