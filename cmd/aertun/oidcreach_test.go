// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"testing"
)

// An in-house identity provider is reached inside the ranges declared for
// it and nowhere else private; a hosted one gets the public internet only;
// a range that would take in cloud metadata, or a whole private network
// and more, is refused at configure time.
func TestAnInHouseProviderIsReachedOnlyInsideItsRanges(t *testing.T) {
	f, err := oidcFetcher(&oidcConfig{Reach: []string{"10.20.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	if why := f.Reach(net.ParseIP("10.20.1.5")); why != "" {
		t.Errorf("the declared range was refused: %s", why)
	}
	if why := f.Reach(net.ParseIP("10.30.0.1")); why == "" {
		t.Error("an address outside the declared range was reached")
	}
	if why := f.Reach(net.ParseIP("169.254.169.254")); why == "" {
		t.Error("cloud metadata was reached")
	}
	hosted, err := oidcFetcher(&oidcConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hosted.Reach != nil {
		t.Error("a hosted provider was given a private reach")
	}
	for _, bad := range []string{"169.254.0.0/16", "10.0.0.0/7", "not-a-range", "10.20.0.1/16"} {
		if _, err := parseReach([]string{bad}); err == nil {
			t.Errorf("%q was accepted as a range to reach", bad)
		}
	}
	windtunnelOutput(t)
	root := t.TempDir()
	if err := oidcConfigure(root, []string{"--issuer", "https://kc.corp.example/realms/x",
		"--client-id", "aertun", "--redirect-uri", "https://aertun.corp.example/auth/callback",
		"--reach", "169.254.0.0/16"}); err == nil {
		t.Error("configure accepted a range that takes in cloud metadata")
	}
	if err := oidcConfigure(root, []string{"--issuer", "https://kc.corp.example/realms/x",
		"--client-id", "aertun", "--redirect-uri", "https://aertun.corp.example/auth/callback",
		"--reach", "10.20.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOIDC(root)
	if err != nil || cfg == nil || len(cfg.Reach) != 1 || cfg.Reach[0] != "10.20.0.0/16" {
		t.Fatalf("the saved configuration: %+v %v", cfg, err)
	}
}
