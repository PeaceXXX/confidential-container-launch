// Package launch is the launch gate for a confidential container.
//
// Decision flow, in order:
//  1. measurement match: every expected measurement in the manifest must
//     equal the evidence (MRTD, MRCONFIGID, RTMR0-3);
//  2. nonce binding: REPORTDATA must commit to the manifest's fresh nonce,
//     so stale evidence cannot be replayed;
//  3. TCB floor: TEE_TCB_SVN (component-wise), QE SVN and PCE SVN must meet
//     the manifest minimums.
//
// Only when all three pass does the gate derive a workload key from the
// evidence measurements and seal the workload's secrets under it. The key
// is bound to MRTD + MRCONFIGID + RTMR2, so the sealed bundle can only be
// opened by a container whose measurements still match: change one runtime
// measurement and decryption fails closed (AES-GCM authentication).
package launch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/PeaceXXX/confidential-container-launch/internal/evidence"
)

// Manifest is the operator's launch policy for one workload.
type Manifest struct {
	Workload string `json:"workload"`
	Image    string `json:"image"` // image reference incl. digest
	Nonce    string `json:"nonce"` // fresh per launch request
	Expected struct {
		MrTd       string `json:"mr_td"`
		MrConfigID string `json:"mr_config_id"`
		Rtmr0      string `json:"rtmr0"`
		Rtmr1      string `json:"rtmr1"`
		Rtmr2      string `json:"rtmr2"`
		Rtmr3      string `json:"rtmr3"`
	} `json:"expected"`
	MinTeeTcbSvn string `json:"min_tee_tcb_svn"` // hex, 16 bytes
	MinQeSvn     int    `json:"min_qe_svn"`
	MinPceSvn    int    `json:"min_pce_svn"`
}

// LoadManifest reads a manifest file.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Workload == "" || m.Image == "" || m.Nonce == "" {
		return nil, fmt.Errorf("manifest needs workload, image and nonce")
	}
	return &m, nil
}

// Check is one gate decision with a human-readable reason.
type Check struct {
	Name   string `json:"name"`
	Result string `json:"result"` // "pass" or "fail"
	Detail string `json:"detail"`
}

// SealedSecret is one AES-256-GCM sealed value.
type SealedSecret struct {
	Nonce      string `json:"nonce_b64"`
	Ciphertext string `json:"ciphertext_b64"`
}

// Plan is the gate's output: the decision, every check, and (on ALLOW only)
// the sealed secrets.
type Plan struct {
	Decision string                  `json:"decision"` // ALLOW or DENY
	Workload string                  `json:"workload"`
	Image    string                  `json:"image"`
	Checks   []Check                 `json:"checks"`
	KeyID    string                  `json:"key_id,omitempty"` // hex, SHA-256 of the derived key
	Sealed   map[string]SealedSecret `json:"sealed,omitempty"`
}

func pass(name, detail string) Check { return Check{Name: name, Result: "pass", Detail: detail} }
func fail(name, detail string) Check { return Check{Name: name, Result: "fail", Detail: detail} }

// Evaluate runs the gate. It never returns an error for a DENY: a failed
// check is a decision, not a crash. Errors are only for malformed inputs.
func Evaluate(m *Manifest, ev *evidence.Evidence, secrets map[string]string) (*Plan, error) {
	plan := &Plan{Decision: "ALLOW", Workload: m.Workload, Image: m.Image}

	// 1. Measurement match.
	for _, name := range []string{"mr_td", "mr_config_id", "rtmr0", "rtmr1", "rtmr2", "rtmr3"} {
		want := expectedValue(m, name)
		got, err := ev.Measurement(name)
		if err != nil {
			return nil, err
		}
		wantBytes, err := hex.DecodeString(strings.TrimSpace(want))
		if err != nil || len(wantBytes) != 48 {
			plan.Checks = append(plan.Checks, fail("measurement:"+name, "manifest value is not 48-byte hex"))
			plan.Decision = "DENY"
			continue
		}
		if string(got) == string(wantBytes) {
			plan.Checks = append(plan.Checks, pass("measurement:"+name, "matches manifest"))
		} else {
			plan.Checks = append(plan.Checks, fail("measurement:"+name, "evidence differs from manifest"))
			plan.Decision = "DENY"
		}
	}

	// 2. Nonce binding (freshness / anti-replay).
	bound, err := ev.NonceBound(m.Nonce)
	if err != nil {
		return nil, err
	}
	if bound {
		plan.Checks = append(plan.Checks, pass("nonce-binding", "REPORTDATA commits to manifest nonce"))
	} else {
		plan.Checks = append(plan.Checks, fail("nonce-binding", "REPORTDATA does not commit to manifest nonce; evidence may be replayed"))
		plan.Decision = "DENY"
	}

	// 3. TCB floor.
	svn, err := hex.DecodeString(strings.TrimSpace(ev.TeeTcbSvn))
	if err != nil {
		return nil, fmt.Errorf("tee_tcb_svn: %w", err)
	}
	minSvn, err := hex.DecodeString(strings.TrimSpace(m.MinTeeTcbSvn))
	if err != nil || len(minSvn) != 16 {
		plan.Checks = append(plan.Checks, fail("tcb-floor", "manifest min_tee_tcb_svn is not 16-byte hex"))
		plan.Decision = "DENY"
	} else if svnAtLeast(svn, minSvn) {
		plan.Checks = append(plan.Checks, pass("tcb-floor", "TEE_TCB_SVN meets minimum"))
	} else {
		plan.Checks = append(plan.Checks, fail("tcb-floor", "TEE_TCB_SVN below minimum"))
		plan.Decision = "DENY"
	}
	if ev.QeSvn >= m.MinQeSvn {
		plan.Checks = append(plan.Checks, pass("qe-svn", fmt.Sprintf("%d >= %d", ev.QeSvn, m.MinQeSvn)))
	} else {
		plan.Checks = append(plan.Checks, fail("qe-svn", fmt.Sprintf("%d < %d", ev.QeSvn, m.MinQeSvn)))
		plan.Decision = "DENY"
	}
	if ev.PceSvn >= m.MinPceSvn {
		plan.Checks = append(plan.Checks, pass("pce-svn", fmt.Sprintf("%d >= %d", ev.PceSvn, m.MinPceSvn)))
	} else {
		plan.Checks = append(plan.Checks, fail("pce-svn", fmt.Sprintf("%d < %d", ev.PceSvn, m.MinPceSvn)))
		plan.Decision = "DENY"
	}

	if plan.Decision == "DENY" {
		return plan, nil
	}

	// All checks passed: derive the measurement-bound key and seal.
	key, err := DeriveKey(ev)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	plan.KeyID = hex.EncodeToString(sum[:])
	plan.Sealed = make(map[string]SealedSecret, len(secrets))
	for name, value := range secrets {
		s, err := Seal(key, value)
		if err != nil {
			return nil, err
		}
		plan.Sealed[name] = s
	}
	return plan, nil
}

// svnAtLeast is a component-wise comparison: every SVN component in got must
// be at least the corresponding component in min. A single lagging component
// (e.g. an unpatched microcode level) fails the gate even if others are ahead.
func svnAtLeast(got, min []byte) bool {
	if len(got) != len(min) {
		return false
	}
	for i := range got {
		if got[i] < min[i] {
			return false
		}
	}
	return true
}

// DeriveKey derives the workload key from the evidence measurements. Binding
// to MRTD (the TD image), MRCONFIGID (launch configuration) and RTMR2
// (runtime/container configuration) means any of those changing produces a
// different key, so sealed secrets cannot follow a tampered container.
func DeriveKey(ev *evidence.Evidence) ([]byte, error) {
	mrtd, err := ev.Measurement("mr_td")
	if err != nil {
		return nil, err
	}
	mrcfg, err := ev.Measurement("mr_config_id")
	if err != nil {
		return nil, err
	}
	rtmr2, err := ev.Measurement("rtmr2")
	if err != nil {
		return nil, err
	}
	ikm := append(append(append([]byte{}, mrtd...), mrcfg...), rtmr2...)
	salt := sha256.Sum256([]byte("coco-launch-v1"))
	return hkdfSHA256(salt[:], ikm, []byte("coco-launch secret release v1"), 32), nil
}

// hkdfSHA256 is HKDF (RFC 5869) with SHA-256, implemented on stdlib HMAC so
// this module has no external dependencies.
func hkdfSHA256(salt, ikm, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	var okm, t []byte
	for i := byte(1); len(okm) < length; i++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

// Seal encrypts one secret value under key with AES-256-GCM.
func Seal(key []byte, plaintext string) (SealedSecret, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return SealedSecret{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return SealedSecret{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return SealedSecret{}, err
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return SealedSecret{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Unseal re-derives the key from the *presented* evidence and decrypts the
// sealed bundle. In a real deployment the presented evidence is the TEE's
// own self-measurement at container start; here the CLI takes an evidence
// file as its proxy. If any bound measurement drifted, the derived key
// differs and GCM authentication fails: the secret is never released.
func Unseal(ev *evidence.Evidence, sealed map[string]SealedSecret) (map[string]string, error) {
	key, err := DeriveKey(ev)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(sealed))
	for name, s := range sealed {
		nonce, err := base64.StdEncoding.DecodeString(s.Nonce)
		if err != nil {
			return nil, fmt.Errorf("%s: bad nonce: %w", name, err)
		}
		ct, err := base64.StdEncoding.DecodeString(s.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("%s: bad ciphertext: %w", name, err)
		}
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: authentication failed; measurements drifted or bundle tampered", name)
		}
		out[name] = string(pt)
	}
	return out, nil
}

func expectedValue(m *Manifest, name string) string {
	switch name {
	case "mr_td":
		return m.Expected.MrTd
	case "mr_config_id":
		return m.Expected.MrConfigID
	case "rtmr0":
		return m.Expected.Rtmr0
	case "rtmr1":
		return m.Expected.Rtmr1
	case "rtmr2":
		return m.Expected.Rtmr2
	case "rtmr3":
		return m.Expected.Rtmr3
	}
	return ""
}
