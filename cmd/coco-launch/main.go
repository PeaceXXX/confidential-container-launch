// Command coco-launch is the confidential-container launch gate: verify
// attestation evidence against a workload manifest, and on ALLOW seal the
// workload's secrets under a measurement-bound key.
//
// Usage:
//
//	coco-launch gen-sample --out-dir examples
//	coco-launch launch --manifest manifest.json --evidence evidence.json --secrets secrets.json --out plan.json
//	coco-launch unseal --bundle plan.json --evidence evidence.json [--out secrets.out.json]
//	coco-launch inspect --evidence evidence.json
package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PeaceXXX/confidential-container-launch/internal/evidence"
	"github.com/PeaceXXX/confidential-container-launch/internal/launch"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen-sample":
		err = cmdGenSample(os.Args[2:])
	case "launch":
		err = cmdLaunch(os.Args[2:])
	case "unseal":
		err = cmdUnseal(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "coco-launch: confidential-container launch gate")
	fmt.Fprintln(os.Stderr, "commands: gen-sample, launch, unseal, inspect")
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// sampleDigest returns a deterministic 48-byte measurement: SHA-384(label).
func sampleDigest(label string) string {
	sum := sha512.Sum384([]byte(label))
	return hex.EncodeToString(sum[:])
}

func cmdGenSample(args []string) error {
	fs := flag.NewFlagSet("gen-sample", flag.ExitOnError)
	outDir := fs.String("out-dir", "examples", "directory to write sample files into")
	fs.Parse(args)
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	nonce := "launch-2026-11-02-demo-nonce"
	nonceHash := sha256.Sum256([]byte(nonce))
	reportData := append(append([]byte{}, nonceHash[:]...), make([]byte, 32)...)

	ev := &evidence.Evidence{
		Version:    4,
		TEEType:    "tdx",
		MrTd:       sampleDigest("demo-mrtd: fraud-scoring v1.2.0"),
		MrConfigID: sampleDigest("demo-mrconfigid: 4vcpu 8gb no-debug"),
		MrOwner:    sampleDigest("demo-mrowner: operator-key-1"),
		Rtmr0:      sampleDigest("demo-rtmr0: firmware"),
		Rtmr1:      sampleDigest("demo-rtmr1: kernel 6.8"),
		Rtmr2:      sampleDigest("demo-rtmr2: container config"),
		Rtmr3:      sampleDigest("demo-rtmr3: workload args"),
		ReportData: hex.EncodeToString(reportData),
		TeeTcbSvn:  "02020202020202020202020202020202",
		QeSvn:      3,
		PceSvn:     4,
	}
	m := &launch.Manifest{Workload: "fraud-scoring-api", Image: "registry.example.com/fraud-scoring@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Nonce: nonce}
	m.Expected.MrTd = ev.MrTd
	m.Expected.MrConfigID = ev.MrConfigID
	m.Expected.Rtmr0 = ev.Rtmr0
	m.Expected.Rtmr1 = ev.Rtmr1
	m.Expected.Rtmr2 = ev.Rtmr2
	m.Expected.Rtmr3 = ev.Rtmr3
	m.MinTeeTcbSvn = "01010101010101010101010101010101"
	m.MinQeSvn = 2
	m.MinPceSvn = 2
	secrets := map[string]string{
		"api_key":     "demo-only-not-a-real-key",
		"db_password": "demo-only-not-a-real-password",
	}
	for name, v := range map[string]any{
		"evidence.json": ev, "manifest.json": m, "secrets.json": secrets,
	} {
		if err := writeJSON(filepath.Join(*outDir, name), v); err != nil {
			return err
		}
	}
	fmt.Printf("wrote sample manifest, evidence and secrets to %s\n", *outDir)
	return nil
}

func cmdLaunch(args []string) error {
	fs := flag.NewFlagSet("launch", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "workload manifest JSON")
	evidencePath := fs.String("evidence", "", "attestation evidence JSON")
	secretsPath := fs.String("secrets", "", "plaintext secrets JSON (name -> value)")
	outPath := fs.String("out", "plan.json", "launch plan output JSON")
	fs.Parse(args)
	if *manifestPath == "" || *evidencePath == "" || *secretsPath == "" {
		return fmt.Errorf("--manifest, --evidence and --secrets are required")
	}
	m, err := launch.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	ev, err := evidence.Load(*evidencePath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*secretsPath)
	if err != nil {
		return err
	}
	var secrets map[string]string
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return fmt.Errorf("parse secrets: %w", err)
	}
	plan, err := launch.Evaluate(m, ev, secrets)
	if err != nil {
		return err
	}
	if err := writeJSON(*outPath, plan); err != nil {
		return err
	}
	for _, c := range plan.Checks {
		fmt.Printf("[%s] %s: %s\n", c.Result, c.Name, c.Detail)
	}
	fmt.Printf("decision: %s (plan written to %s)\n", plan.Decision, *outPath)
	if plan.Decision == "DENY" {
		return fmt.Errorf("launch denied")
	}
	return nil
}

func cmdUnseal(args []string) error {
	fs := flag.NewFlagSet("unseal", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "launch plan JSON from a successful launch")
	evidencePath := fs.String("evidence", "", "evidence JSON presented at unseal time")
	outPath := fs.String("out", "", "optional output file (default: stdout)")
	fs.Parse(args)
	if *bundlePath == "" || *evidencePath == "" {
		return fmt.Errorf("--bundle and --evidence are required")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	var plan launch.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	if plan.Decision != "ALLOW" || len(plan.Sealed) == 0 {
		return fmt.Errorf("bundle is not an ALLOW plan with sealed secrets")
	}
	ev, err := evidence.Load(*evidencePath)
	if err != nil {
		return err
	}
	secrets, err := launch.Unseal(ev, plan.Sealed)
	if err != nil {
		return err
	}
	if *outPath == "" {
		enc, _ := json.MarshalIndent(secrets, "", "  ")
		fmt.Println(string(enc))
		return nil
	}
	return writeJSON(*outPath, secrets)
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	evidencePath := fs.String("evidence", "", "evidence JSON")
	fs.Parse(args)
	if *evidencePath == "" {
		return fmt.Errorf("--evidence is required")
	}
	ev, err := evidence.Load(*evidencePath)
	if err != nil {
		return err
	}
	fmt.Printf("quote version: %d  tee: %s  qe_svn: %d  pce_svn: %d  tee_tcb_svn: %s\n",
		ev.Version, ev.TEEType, ev.QeSvn, ev.PceSvn, ev.TeeTcbSvn)
	for _, name := range []string{"mr_td", "mr_config_id", "mr_owner", "rtmr0", "rtmr1", "rtmr2", "rtmr3"} {
		b, _ := ev.Measurement(name)
		fmt.Printf("%-13s %s\n", name, hex.EncodeToString(b))
	}
	fmt.Printf("report_data   %s\n", ev.ReportData)
	return nil
}
