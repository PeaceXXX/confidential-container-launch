// Package evidence models the attestation evidence a confidential-container
// host presents before a workload is launched.
//
// This is a deliberately small, JSON-shaped subset of what a real TDX quote
// carries: the measurements a launch gate actually decides on (MRTD,
// MRCONFIGID, the four runtime measurement registers RTMR0-3), the TCB
// security version numbers, and the 64-byte REPORTDATA used for nonce
// binding. Real quote parsing (binary layout, certificate chain, signature
// verification) is out of scope here; see the README Limitations section.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Evidence is one attestation report from a confidential-container host.
type Evidence struct {
	Version    int    `json:"version"`
	TEEType    string `json:"tee_type"` // "tdx" for this demo
	MrTd       string `json:"mr_td"`    // hex, 48 bytes
	MrConfigID string `json:"mr_config_id"`
	MrOwner    string `json:"mr_owner"`
	Rtmr0      string `json:"rtmr0"`
	Rtmr1      string `json:"rtmr1"`
	Rtmr2      string `json:"rtmr2"`
	Rtmr3      string `json:"rtmr3"`
	ReportData string `json:"report_data"` // hex, 64 bytes
	// TeeTcbSvn is 16 bytes, hex-encoded. Each byte is one SVN component.
	TeeTcbSvn string `json:"tee_tcb_svn"`
	QeSvn     int    `json:"qe_svn"`
	PceSvn    int    `json:"pce_svn"`
}

// Load reads and validates an evidence file.
func Load(path string) (*Evidence, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ev Evidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, fmt.Errorf("parse evidence: %w", err)
	}
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	return &ev, nil
}

// Validate checks structure only: lengths, hex, TEE type. It never claims
// the evidence is authentic; authenticity (signature, cert chain, collateral)
// is a separate verifier's job.
func (e *Evidence) Validate() error {
	if e.Version != 4 {
		return fmt.Errorf("unsupported quote version %d (want 4)", e.Version)
	}
	if !strings.EqualFold(e.TEEType, "tdx") {
		return fmt.Errorf("unsupported tee_type %q (want tdx)", e.TEEType)
	}
	for _, m := range []struct {
		name, hexv string
	}{
		{"mr_td", e.MrTd}, {"mr_config_id", e.MrConfigID}, {"mr_owner", e.MrOwner},
		{"rtmr0", e.Rtmr0}, {"rtmr1", e.Rtmr1}, {"rtmr2", e.Rtmr2}, {"rtmr3", e.Rtmr3},
	} {
		if _, err := decodeHex(m.hexv, 48); err != nil {
			return fmt.Errorf("%s: %w", m.name, err)
		}
	}
	if _, err := decodeHex(e.ReportData, 64); err != nil {
		return fmt.Errorf("report_data: %w", err)
	}
	if _, err := decodeHex(e.TeeTcbSvn, 16); err != nil {
		return fmt.Errorf("tee_tcb_svn: %w", err)
	}
	if e.QeSvn < 0 || e.PceSvn < 0 {
		return fmt.Errorf("qe_svn and pce_svn must be non-negative")
	}
	return nil
}

// Measurement returns the raw bytes of a named measurement register.
func (e *Evidence) Measurement(name string) ([]byte, error) {
	var hexv string
	switch name {
	case "mr_td":
		hexv = e.MrTd
	case "mr_config_id":
		hexv = e.MrConfigID
	case "mr_owner":
		hexv = e.MrOwner
	case "rtmr0":
		hexv = e.Rtmr0
	case "rtmr1":
		hexv = e.Rtmr1
	case "rtmr2":
		hexv = e.Rtmr2
	case "rtmr3":
		hexv = e.Rtmr3
	default:
		return nil, fmt.Errorf("unknown measurement %q", name)
	}
	return decodeHex(hexv, 48)
}

// NonceBound reports whether REPORTDATA binds this evidence to nonce: the
// first 32 bytes of REPORTDATA must equal SHA-256(nonce). Binding the launch
// request's fresh nonce into the report is what stops an attacker replaying
// last week's good evidence for today's launch.
func (e *Evidence) NonceBound(nonce string) (bool, error) {
	rd, err := decodeHex(e.ReportData, 64)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256([]byte(nonce))
	return string(rd[:32]) == string(sum[:]), nil
}

func decodeHex(s string, want int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != want {
		return nil, fmt.Errorf("want %d bytes, got %d", want, len(b))
	}
	return b, nil
}
