/**
 * Merkle Tree for Transcript Integrity
 *
 * Architecture:
 *   - Each approved semester record = one Merkle leaf
 *   - Leaf hash = SHA256(recordID | semester | SGPA | CGPA | studentID)
 *   - Tree built bottom-up; odd number of leaves = last leaf duplicated
 *   - Root stored on-chain at "MERKLE_<studentID>"
 *
 * Use cases:
 *   1. BuildTranscriptMerkleTree  — admin/dept calls this after final approval
 *   2. GetTranscriptMerkleRoot    — anyone can read the root (public audit)
 *   3. GenerateMerkleProof        — generates proof path for ONE semester record
 *   4. VerifyMerkleProof          — any verifier proves one record is in the transcript
 *                                   WITHOUT seeing all other semester records
 *
 * Why this matters (selective disclosure):
 *   A company checking "did this student pass Semester 3?" gets a proof for
 *   Semester 3 only. They verify it against the public root. They learn nothing
 *   about Semesters 1, 2, 4, 5, 6, 7, 8.
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ── Data Types ────────────────────────────────────────────────────────────────

// MerkleLeafData is the canonical data hashed to create a leaf.
// Deterministic: same record always produces same leaf hash.
type MerkleLeafData struct {
	RecordID  string  `json:"recordId"`
	StudentID string  `json:"studentId"`
	Semester  int     `json:"semester"`
	SGPA      float64 `json:"sgpa"`
	CGPA      float64 `json:"cgpa"`
}

// ProofNode is one step in the Merkle proof path.
type ProofNode struct {
	Hash     string `json:"hash"`     // hex-encoded SHA256
	Position string `json:"position"` // "left" or "right"
}

// MerkleProof is the full proof for one leaf. Given to a verifier.
type MerkleProof struct {
	StudentID string      `json:"studentId"`
	RecordID  string      `json:"recordId"`
	LeafHash  string      `json:"leafHash"`  // the leaf's own hash
	Root      string      `json:"root"`      // Merkle root to verify against
	ProofPath []ProofNode `json:"proofPath"` // sibling hashes from leaf to root
	LeafIndex int         `json:"leafIndex"` // position in the leaf array
	Semester  int         `json:"semester"`
	SGPA      float64     `json:"sgpa"`
	CGPA      float64     `json:"cgpa"`
}

// TranscriptMerkleRoot is stored on-chain.
// Key: "MERKLE_<studentID>"
type TranscriptMerkleRoot struct {
	StudentID  string    `json:"studentId"`
	Root       string    `json:"root"` // hex-encoded root hash
	LeafCount  int       `json:"leafCount"`
	RecordIDs  []string  `json:"recordIds"` // ordered — determines leaf positions
	ComputedAt time.Time `json:"computedAt"`
	ComputedBy string    `json:"computedBy"` // MSP that built it
	TxID       string    `json:"txId"`
}

const merklePrefixKey = "MERKLE_"

// ── Core Merkle Helpers ───────────────────────────────────────────────────────

// hashLeaf creates a deterministic SHA256 hash for a single semester record leaf.
func hashLeaf(data MerkleLeafData) string {
	raw := fmt.Sprintf("%s|%s|%d|%.4f|%.4f",
		data.RecordID, data.StudentID, data.Semester, data.SGPA, data.CGPA)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// hashPair combines two hashes into one parent hash (sorted to ensure determinism).
func hashPair(left, right string) string {
	// Sort so that hash(A,B) == hash(B,A) — makes proof verification order-independent
	if left > right {
		left, right = right, left
	}
	combined := left + right
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])
}

// buildTree constructs a full Merkle tree from leaves and returns all levels.
// levels[0] = leaf level, levels[last] = [root]
func buildTree(leaves []string) [][]string {
	if len(leaves) == 0 {
		return nil
	}
	levels := [][]string{leaves}
	current := leaves
	for len(current) > 1 {
		var next []string
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			right := left // duplicate if odd
			if i+1 < len(current) {
				right = current[i+1]
			}
			next = append(next, hashPair(left, right))
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

// generateProof builds the sibling path from a leaf at leafIndex to the root.
func generateProof(levels [][]string, leafIndex int) []ProofNode {
	var proof []ProofNode
	idx := leafIndex
	for i := 0; i < len(levels)-1; i++ {
		level := levels[i]
		var sibling ProofNode
		if idx%2 == 0 {
			// Current is left child → sibling is right
			sibIdx := idx + 1
			if sibIdx >= len(level) {
				sibIdx = idx // duplicate (odd)
			}
			sibling = ProofNode{Hash: level[sibIdx], Position: "right"}
		} else {
			// Current is right child → sibling is left
			sibling = ProofNode{Hash: level[idx-1], Position: "left"}
		}
		proof = append(proof, sibling)
		idx /= 2
	}
	return proof
}

// verifyProof recomputes the root from a leaf hash + proof path and checks it matches.
func verifyProof(leafHash string, proof []ProofNode, expectedRoot string) bool {
	current := leafHash
	for _, node := range proof {
		if node.Position == "right" {
			current = hashPair(current, node.Hash)
		} else {
			current = hashPair(node.Hash, current)
		}
	}
	return current == expectedRoot
}

// ── Chaincode Functions ───────────────────────────────────────────────────────

// BuildTranscriptMerkleTree builds a Merkle tree from all APPROVED semester
// records for a student and stores the root on-chain.
// Must be called by NITWarangalMSP or DepartmentsMSP.
func (s *SmartContract) BuildTranscriptMerkleTree(
	ctx contractapi.TransactionContextInterface,
	studentID string,
) (*TranscriptMerkleRoot, error) {
	if err := checkMSPAccess(ctx, NITWarangalMSP, DepartmentsMSP); err != nil {
		return nil, err
	}

	// Verify student exists
	exists, err := s.StudentExists(ctx, studentID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("student %s does not exist", studentID)
	}

	// Fetch all academic records for this student
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(StudentRecordKey, []string{studentID})
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %v", err)
	}
	defer iter.Close()

	type recordEntry struct {
		id       string
		semester int
		sgpa     float64
		cgpa     float64
	}
	var records []recordEntry

	for iter.HasNext() {
		result, err := iter.Next()
		if err != nil {
			continue
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(result.Key)
		if err != nil || len(parts) < 2 {
			continue
		}
		recordID := parts[1]
		recJSON, err := ctx.GetStub().GetState(recordID)
		if err != nil || recJSON == nil {
			continue
		}
		var rec AcademicRecord
		if err := json.Unmarshal(recJSON, &rec); err != nil {
			continue
		}
		// Only include APPROVED records in the Merkle tree
		if rec.Status != RecordApproved {
			continue
		}
		records = append(records, recordEntry{
			id:       recordID,
			semester: rec.Semester,
			sgpa:     rec.SGPA,
			cgpa:     rec.CGPA,
		})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no approved records found for student %s — Merkle tree requires at least one approved record", studentID)
	}

	// Sort records by semester for deterministic leaf ordering
	sort.Slice(records, func(i, j int) bool {
		return records[i].semester < records[j].semester
	})

	// Build leaf hashes
	leaves := make([]string, len(records))
	recordIDs := make([]string, len(records))
	for i, rec := range records {
		leaves[i] = hashLeaf(MerkleLeafData{
			RecordID:  rec.id,
			StudentID: studentID,
			Semester:  rec.semester,
			SGPA:      rec.sgpa,
			CGPA:      rec.cgpa,
		})
		recordIDs[i] = rec.id
	}

	// Build Merkle tree
	levels := buildTree(leaves)
	root := levels[len(levels)-1][0]

	callerMSP, _ := ctx.GetClientIdentity().GetMSPID()
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	computedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	merkleRoot := TranscriptMerkleRoot{
		StudentID:  studentID,
		Root:       root,
		LeafCount:  len(leaves),
		RecordIDs:  recordIDs,
		ComputedAt: computedAt,
		ComputedBy: callerMSP,
		TxID:       ctx.GetStub().GetTxID(),
	}

	rootJSON, err := json.Marshal(merkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Merkle root: %v", err)
	}

	key := merklePrefixKey + studentID
	if err := ctx.GetStub().PutState(key, rootJSON); err != nil {
		return nil, fmt.Errorf("failed to store Merkle root: %v", err)
	}

	// Emit event
	eventData, _ := json.Marshal(map[string]interface{}{
		"studentId": studentID,
		"root":      root,
		"leafCount": len(leaves),
	})
	ctx.GetStub().SetEvent("MerkleTreeBuilt", eventData)

	return &merkleRoot, nil
}

// GetTranscriptMerkleRoot returns the stored Merkle root for a student.
// Public — anyone can call this to audit the commitment.
func (s *SmartContract) GetTranscriptMerkleRoot(
	ctx contractapi.TransactionContextInterface,
	studentID string,
) (*TranscriptMerkleRoot, error) {
	key := merklePrefixKey + studentID
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read Merkle root: %v", err)
	}
	if data == nil {
		return nil, fmt.Errorf("no Merkle root found for student %s — call BuildTranscriptMerkleTree first", studentID)
	}

	var root TranscriptMerkleRoot
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	return &root, nil
}

// GenerateMerkleProof produces a proof that a specific semester record belongs
// to the transcript Merkle tree. Returns the proof path for the verifier.
// The verifier does NOT need to see any other records to verify this proof.
func (s *SmartContract) GenerateMerkleProof(
	ctx contractapi.TransactionContextInterface,
	studentID, recordID string,
) (*MerkleProof, error) {
	// Load stored root (which includes the ordered record list)
	merkleRoot, err := s.GetTranscriptMerkleRoot(ctx, studentID)
	if err != nil {
		return nil, err
	}

	// Find record position in the ordered leaf array
	leafIndex := -1
	for i, id := range merkleRoot.RecordIDs {
		if id == recordID {
			leafIndex = i
			break
		}
	}
	if leafIndex == -1 {
		return nil, fmt.Errorf("record %s is not in the Merkle tree for student %s (tree may be stale — rebuild it)", recordID, studentID)
	}

	// Fetch the actual record to get SGPA/CGPA for the leaf hash
	recJSON, err := ctx.GetStub().GetState(recordID)
	if err != nil || recJSON == nil {
		return nil, fmt.Errorf("record %s not found on ledger", recordID)
	}
	var rec AcademicRecord
	if err := json.Unmarshal(recJSON, &rec); err != nil {
		return nil, err
	}

	// Rebuild all leaves (needed to reconstruct proof path)
	leaves := make([]string, len(merkleRoot.RecordIDs))
	for i, rid := range merkleRoot.RecordIDs {
		recJ, _ := ctx.GetStub().GetState(rid)
		var r AcademicRecord
		_ = json.Unmarshal(recJ, &r)
		leaves[i] = hashLeaf(MerkleLeafData{
			RecordID:  rid,
			StudentID: studentID,
			Semester:  r.Semester,
			SGPA:      r.SGPA,
			CGPA:      r.CGPA,
		})
	}

	levels := buildTree(leaves)
	proofPath := generateProof(levels, leafIndex)
	leafHash := leaves[leafIndex]

	return &MerkleProof{
		StudentID: studentID,
		RecordID:  recordID,
		LeafHash:  leafHash,
		Root:      merkleRoot.Root,
		ProofPath: proofPath,
		LeafIndex: leafIndex,
		Semester:  rec.Semester,
		SGPA:      rec.SGPA,
		CGPA:      rec.CGPA,
	}, nil
}

// VerifyMerkleProof verifies that a given proof is valid against the on-chain root.
// Called by verifiers — they pass the proof they received; chaincode checks it.
// Returns true if the proof is valid (record is genuinely part of the transcript).
func (s *SmartContract) VerifyMerkleProof(
	ctx contractapi.TransactionContextInterface,
	studentID, recordID, proofJSON string,
) (bool, error) {
	// Load stored root
	merkleRoot, err := s.GetTranscriptMerkleRoot(ctx, studentID)
	if err != nil {
		return false, err
	}

	// Parse the proof
	var proof MerkleProof
	if err := json.Unmarshal([]byte(proofJSON), &proof); err != nil {
		return false, fmt.Errorf("invalid proof JSON: %v", err)
	}

	// Sanity checks
	if proof.StudentID != studentID || proof.RecordID != recordID {
		return false, fmt.Errorf("proof is for a different student or record")
	}

	// Recompute leaf hash from the proof's claimed SGPA/CGPA/semester
	recomputedLeaf := hashLeaf(MerkleLeafData{
		RecordID:  recordID,
		StudentID: studentID,
		Semester:  proof.Semester,
		SGPA:      proof.SGPA,
		CGPA:      proof.CGPA,
	})

	// Leaf hash in proof must match recomputed one (data integrity)
	if recomputedLeaf != proof.LeafHash {
		return false, fmt.Errorf("leaf hash mismatch — SGPA/CGPA in proof does not match claimed values")
	}

	// Verify proof path leads to the on-chain root
	valid := verifyProof(proof.LeafHash, proof.ProofPath, merkleRoot.Root)
	if !valid {
		return false, fmt.Errorf("Merkle proof INVALID — record %s is not part of the committed transcript", recordID)
	}

	// Emit verification event (for audit trail)
	verifierMSP, _ := ctx.GetClientIdentity().GetMSPID()
	eventData, _ := json.Marshal(map[string]interface{}{
		"studentId":  studentID,
		"recordId":   recordID,
		"verifiedBy": verifierMSP,
		"semester":   proof.Semester,
		"valid":      true,
	})
	ctx.GetStub().SetEvent("MerkleProofVerified", eventData)

	return true, nil
}
