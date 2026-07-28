package access

import (
	"errors"
	"strings"
)

type Role string

const (
	RoleReader      Role = "reader"
	RoleContributor Role = "contributor"
	RoleAdmin       Role = "admin"
)

type Capability string

const (
	CapabilityPull          Capability = "pull"
	CapabilityPush          Capability = "push"
	CapabilityReadHistory   Capability = "read_history"
	CapabilityDeleteHistory Capability = "delete_history"
	CapabilityManage        Capability = "manage"
)

var ErrInvalidRole = errors.New("role must be reader, contributor, or admin")

func ParseRole(value string) (Role, error) {
	role := Role(strings.ToLower(strings.TrimSpace(value)))
	switch role {
	case RoleReader, RoleContributor, RoleAdmin:
		return role, nil
	default:
		return "", ErrInvalidRole
	}
}

func (r Role) Can(capability Capability) bool {
	switch r {
	case RoleReader:
		return capability == CapabilityPull || capability == CapabilityReadHistory
	case RoleContributor:
		return capability == CapabilityPull ||
			capability == CapabilityPush ||
			capability == CapabilityReadHistory
	case RoleAdmin:
		return true
	default:
		return false
	}
}
