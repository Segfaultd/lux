package access

import (
	"errors"
	"testing"
)

func TestParseRole(t *testing.T) {
	for input, want := range map[string]Role{
		"reader": RoleReader, " Contributor ": RoleContributor, "ADMIN": RoleAdmin,
	} {
		got, err := ParseRole(input)
		if err != nil || got != want {
			t.Fatalf("ParseRole(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "owner", "read/write"} {
		if _, err := ParseRole(input); !errors.Is(err, ErrInvalidRole) {
			t.Fatalf("ParseRole(%q) returned %v", input, err)
		}
	}
}

func TestRoleCapabilities(t *testing.T) {
	tests := []struct {
		role       Role
		capability Capability
		want       bool
	}{
		{RoleReader, CapabilityPull, true},
		{RoleReader, CapabilityReadHistory, true},
		{RoleReader, CapabilityPush, false},
		{RoleReader, CapabilityDeleteHistory, false},
		{RoleContributor, CapabilityPush, true},
		{RoleContributor, CapabilityDeleteHistory, false},
		{RoleAdmin, CapabilityManage, true},
		{RoleAdmin, CapabilityDeleteHistory, true},
		{Role("unknown"), CapabilityPull, false},
	}
	for _, test := range tests {
		if got := test.role.Can(test.capability); got != test.want {
			t.Errorf("%s.Can(%s) = %v, want %v", test.role, test.capability, got, test.want)
		}
	}
}
