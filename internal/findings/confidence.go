package findings

import (
	"fmt"
	"math"
	"strings"
)

// ConfidenceLevel says how far the rubric-audited corpus precision of a rule supports trusting
// its findings. The order is the order used by --min-confidence: a rule that was measured and
// found mostly wrong ranks below a rule that was never measured.
type ConfidenceLevel int

const (
	ConfidenceLow       ConfidenceLevel = iota // audited precision below 0.50
	ConfidenceUnaudited                        // no finding of this rule was in the audited sample
	ConfidenceMedium                           // audited precision from 0.50 to below 0.80
	ConfidenceHigh                             // audited precision 0.80 or above
)

var confidenceNames = [...]string{"low", "unaudited", "medium", "high"}

func (c ConfidenceLevel) String() string {
	if c < ConfidenceLow || c > ConfidenceHigh {
		return "unknown"
	}
	return confidenceNames[c]
}

// MarshalText makes confidence levels render as names in JSON.
func (c ConfidenceLevel) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// UnmarshalText parses a confidence level name.
func (c *ConfidenceLevel) UnmarshalText(b []byte) error {
	v, err := ParseConfidence(string(b))
	*c = v
	return err
}

// ParseConfidence parses "low", "unaudited", "medium" or "high".
func ParseConfidence(name string) (ConfidenceLevel, error) {
	for i, n := range confidenceNames {
		if strings.EqualFold(name, n) {
			return ConfidenceLevel(i), nil
		}
	}
	return ConfidenceLow, fmt.Errorf("unknown confidence %q (want low, unaudited, medium or high)", name)
}

// Confidence is the audit record of a rule. Precision is nil when the rule is unaudited.
type Confidence struct {
	Level      ConfidenceLevel `json:"level"`
	Precision  *float64        `json:"precision,omitempty"`
	Correct    int             `json:"correct"`
	Labeled    int             `json:"labeled"`
	MeasuredOn string          `json:"measured_on,omitempty"`
}

// AuditVersion is the scanner release whose findings on the public corpus were rubric-audited.
// The analyzer code of v0.1.0 and v0.1.1 is identical.
const AuditVersion = "v0.1.1"

// audited holds, per rule, the correct and labeled counts of the rubric-audited sample of
// corpus findings (benchmarks/precision/labels.jsonl). TestAuditMatchesLabels fails when the
// two drift apart. Rules without an entry had no finding in the sample.
var audited = map[string][2]int{
	"MCP101": {2, 7},
	"MCP111": {22, 24},
	"MCP121": {2, 11},
	"MCP131": {0, 7},
	"MCP132": {11, 15},
	"MCP141": {12, 15},
	"MCP142": {13, 15},
	"MCP143": {14, 15},
	"MCP144": {15, 15},
	"MCP201": {0, 10},
	"MCP204": {0, 15},
	"MCP205": {0, 4},
	"MCP206": {0, 5},
}

// ConfidenceOf returns the audit record of a rule: high from 0.80, medium from 0.50, low below
// that, unaudited when no finding of the rule was labeled.
func ConfidenceOf(ruleID string) Confidence {
	a, ok := audited[ruleID]
	if !ok || a[1] == 0 {
		return Confidence{Level: ConfidenceUnaudited}
	}
	// Compare counts, not floats: correct/labeled >= 0.80 and >= 0.50.
	level := ConfidenceLow
	switch {
	case 5*a[0] >= 4*a[1]:
		level = ConfidenceHigh
	case 2*a[0] >= a[1]:
		level = ConfidenceMedium
	}
	p := math.Round(100*float64(a[0])/float64(a[1])) / 100
	return Confidence{Level: level, Precision: &p, Correct: a[0], Labeled: a[1], MeasuredOn: AuditVersion}
}

// String is the one-line form used in text reports.
func (c Confidence) String() string {
	if c.Precision == nil {
		return "unaudited (rule audit: no finding of this rule was in the sample)"
	}
	return fmt.Sprintf("%s (rule audit: %d of %d corpus findings correct, precision %.2f, %s)", c.Level, c.Correct, c.Labeled, *c.Precision, c.MeasuredOn)
}
