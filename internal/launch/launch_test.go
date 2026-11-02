package launch

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PeaceXXX/confidential-container-launch/internal/evidence"
)

func testManifest() *Manifest {
	m := &Manifest{Workload: "demo", Image: "example.com/demo@sha256:aa", Nonce: "nonce-1"}
	m.Expected.MrTd = strings.Repeat("a1", 48)
	m.Expected.MrConfigID = strings.Repeat("b2", 48)
	m.Expected.Rtmr0 = strings.Repeat("c3", 48)
	m.Expected.Rtmr1 = strings.Repeat("d4", 48)
	m.Expected.Rtmr2 = strings.Repeat("e5", 48)
	m.Expected.Rtmr3 = strings.Repeat("f6", 48)
	m.MinTeeTcbSvn = strings.Repeat("01", 16)
	m.MinQeSvn = 2
	m.MinPceSvn = 2
	return m
}

func testEvidence() *evidence.Evidence {
	nonceHash := sha256.Sum256([]byte("nonce-1"))
	rd := append(append([]byte{}, nonceHash[:]...), make([]byte, 32)...)
	return &evidence.Evidence{
		Version: 4, TEEType: "tdx",
		MrTd: strings.Repeat("a1", 48), MrConfigID: strings.Repeat("b2", 48),
		MrOwner: strings.Repeat("07", 48),
		Rtmr0:   strings.Repeat("c3", 48), Rtmr1: strings.Repeat("d4", 48),
		Rtmr2: strings.Repeat("e5", 48), Rtmr3: strings.Repeat("f6", 48),
		ReportData: hex.EncodeToString(rd),
		TeeTcbSvn:  strings.Repeat("02", 16), QeSvn: 3, PceSvn: 4,
	}
}

func TestAllowAndUnsealRoundtrip(t *testing.T) {
	plan, err := Evaluate(testManifest(), testEvidence(), map[string]string{"api_key": "s3cr3t"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Decision != "ALLOW" {
		t.Fatalf("want ALLOW, got %s: %+v", plan.Decision, plan.Checks)
	}
	if len(plan.Sealed) != 1 {
		t.Fatalf("want 1 sealed secret, got %d", len(plan.Sealed))
	}
	out, err := Unseal(testEvidence(), plan.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	if out["api_key"] != "s3cr3t" {
		t.Fatalf("unseal mismatch: %v", out)
	}
}

func TestTamperedMeasurementDenies(t *testing.T) {
	ev := testEvidence()
	ev.Rtmr1 = strings.Repeat("00", 48) // tampered runtime measurement
	plan, err := Evaluate(testManifest(), ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Decision != "DENY" {
		t.Fatalf("want DENY, got %s", plan.Decision)
	}
	if len(plan.Sealed) != 0 {
		t.Fatal("DENY plan must not carry sealed secrets")
	}
}

func TestReplayedEvidenceDenies(t *testing.T) {
	ev := testEvidence()
	ev.ReportData = strings.Repeat("00", 64) // no nonce binding
	plan, err := Evaluate(testManifest(), ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Decision != "DENY" {
		t.Fatalf("want DENY for replayed evidence, got %s", plan.Decision)
	}
}

func TestStaleTcbDenies(t *testing.T) {
	ev := testEvidence()
	ev.TeeTcbSvn = strings.Repeat("00", 16)
	ev.QeSvn = 1
	plan, err := Evaluate(testManifest(), ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Decision != "DENY" {
		t.Fatalf("want DENY for stale TCB, got %s", plan.Decision)
	}
}

func TestDriftedMeasurementCannotUnseal(t *testing.T) {
	plan, err := Evaluate(testManifest(), testEvidence(), map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	drifted := testEvidence()
	drifted.Rtmr2 = strings.Repeat("99", 48) // container config changed after sealing
	if _, err := Unseal(drifted, plan.Sealed); err == nil {
		t.Fatal("unseal with drifted RTMR2 must fail")
	}
}

func TestTamperedBundleCannotUnseal(t *testing.T) {
	plan, err := Evaluate(testManifest(), testEvidence(), map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	s := plan.Sealed["k"]
	s.Ciphertext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	plan.Sealed["k"] = s
	if _, err := Unseal(testEvidence(), plan.Sealed); err == nil {
		t.Fatal("unseal of tampered bundle must fail")
	}
}

func TestBadEvidenceRejected(t *testing.T) {
	ev := testEvidence()
	ev.MrTd = "zz" // not hex
	if err := ev.Validate(); err == nil {
		t.Fatal("non-hex measurement must fail validation")
	}
	ev = testEvidence()
	ev.Version = 3
	if err := ev.Validate(); err == nil {
		t.Fatal("version != 4 must fail validation")
	}
}
