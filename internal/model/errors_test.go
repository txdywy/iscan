package model_test

import (
	"testing"

	"iscan/internal/model"
)

func TestIsLocalPermissionError(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"operation not permitted", true},
		{"Permission denied", true},
		{"PERMISSION DENIED", true},
		{"some other error", false},
		{"", false},
		{"operation not", false},
	}
	for _, c := range cases {
		got := model.IsLocalPermissionError(c.input)
		if got != c.want {
			t.Errorf("IsLocalPermissionError(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestTargetValidate(t *testing.T) {
	cases := []struct {
		name    string
		target  model.Target
		wantErr bool
	}{
		{"valid https", model.Target{Name: "a", Domain: "x.com", Scheme: "https", Ports: []int{443}}, false},
		{"valid http", model.Target{Name: "a", Domain: "x.com", Scheme: "http", Ports: []int{80}}, false},
		{"missing name", model.Target{Domain: "x.com", Scheme: "https", Ports: []int{443}}, true},
		{"missing domain", model.Target{Name: "a", Scheme: "https", Ports: []int{443}}, true},
		{"invalid scheme", model.Target{Name: "a", Domain: "x.com", Scheme: "ftp", Ports: []int{443}}, true},
		{"missing ports", model.Target{Name: "a", Domain: "x.com", Scheme: "https"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.target.Validate()
			if c.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
