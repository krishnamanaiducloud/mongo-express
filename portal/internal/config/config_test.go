package config

import (
	"strings"
	"testing"
)

const valid = `
environment: test
identity:
  mode: header
  developerGroups: [devs]
  sreGroups: [sres]
profiles:
  - name: primary
    uri: mongodb://mongo-0.mongo:27017,mongo-1.mongo:27017/?replicaSet=rs0
    tls:
      mode: disabled
`

func TestParseValidAndDefaults(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.ListenAddress != "127.0.0.1:8080" || c.Session.IdleTimeout == 0 || !*c.Session.SecureCookie {
		t.Fatalf("defaults not applied: %+v", c.Server)
	}
	p, ok := c.Profile("primary")
	if !ok || p.DefaultAuthSource != "admin" || len(p.AuthMechanisms) != 2 {
		t.Fatalf("profile defaults: %+v", p)
	}
}

func TestRejectsUnsafeConfig(t *testing.T) {
	cases := map[string]string{
		"missing tls mode":         strings.Replace(valid, "mode: disabled", "caFile: /x", 1),
		"credentials in uri":       strings.Replace(valid, "mongodb://mongo-0", "mongodb://root:pw@mongo-0", 1),
		"tlsInsecure in uri":       strings.Replace(valid, "replicaSet=rs0", "replicaSet=rs0&tlsInsecure=true", 1),
		"tls option in uri":        strings.Replace(valid, "replicaSet=rs0", "replicaSet=rs0&tls=true", 1),
		"verification disabled":    strings.Replace(valid, "mode: disabled", "mode: enabled\n      verifyServerCertificate: false", 1),
		"unknown field":            valid + "\nbogus: 1\n",
		"no groups":                strings.Replace(strings.Replace(valid, "developerGroups: [devs]", "", 1), "sreGroups: [sres]", "", 1),
		"bad identity mode":        strings.Replace(valid, "mode: header", "mode: none", 1),
		"plaintext in production":  strings.Replace(valid, "environment: test", "environment: production", 1),
		"cert files with disabled": strings.Replace(valid, "mode: disabled", "mode: disabled\n      caFile: /ca.pem", 1),
		"bad mechanism":            strings.Replace(valid, "tls:", "authMechanisms: [PLAIN]\n    tls:", 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestProductionPlaintextRequiresApproval(t *testing.T) {
	raw := strings.Replace(valid, "environment: test", "environment: production", 1)
	raw = strings.Replace(raw, "mode: disabled", "mode: disabled\n    plaintextApproved: true\n    securityExceptionRef: SEC-1", 1)
	// plaintextApproved belongs to the profile, not tls: fix indentation.
	raw = strings.Replace(raw, "      mode: disabled\n    plaintextApproved", "      mode: disabled\n    plaintextApproved", 1)
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatalf("approved plaintext should be accepted: %v", err)
	}
}

func TestOpenShiftModeRequiresLoopback(t *testing.T) {
	raw := strings.Replace(valid, "mode: header", "mode: openshift", 1) + "server:\n  listenAddress: 0.0.0.0:8080\n"
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("openshift mode with non-loopback listener must be rejected")
	}
}

func TestDevModeGate(t *testing.T) {
	raw := strings.Replace(valid, "mode: header", "mode: dev\n  dev:\n    user: me\n    groups: [devs]", 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("dev mode without gate must be rejected")
	}
	t.Setenv(DevIdentityGateEnv, "true")
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatalf("dev mode with gate: %v", err)
	}
}

// TestCommittedConfigs validates every configuration file in the repository.
// The production overlay must refuse to start until the MongoDB TLS decision
// is recorded (TLS enabled or plaintext exception approved).
func TestCommittedConfigs(t *testing.T) {
	t.Setenv(DevIdentityGateEnv, "true")
	if _, err := Load("../../config/dev.example.yaml"); err != nil {
		t.Errorf("dev.example.yaml: %v", err)
	}
	for _, env := range []string{"dev", "test"} {
		if _, err := Load("../../../deploy/overlays/" + env + "/config.yaml"); err != nil {
			t.Errorf("overlay %s: %v", env, err)
		}
	}
	if _, err := Load("../../../deploy/base/config.yaml"); err != nil {
		t.Errorf("base: %v", err)
	}
	_, err := Load("../../../deploy/overlays/prod/config.yaml")
	if err == nil || !strings.Contains(err.Error(), "plaintextApproved") {
		t.Errorf("prod overlay must require an explicit plaintext decision, got %v", err)
	}
}

func TestValidateProfileURI(t *testing.T) {
	for _, ok := range []string{"mongodb://a:27017", "mongodb://a,b,c/?replicaSet=rs0&readPreference=secondary", "mongodb+srv://cluster.example.com/"} {
		if err := ValidateProfileURI(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://a", "mongodb://", "mongodb://u@a", "mongodb://a/?authSource=admin", "mongodb://a/?TLSAllowInvalidCertificates=true"} {
		if err := ValidateProfileURI(bad); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}
