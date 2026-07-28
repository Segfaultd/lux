package access

type Capability string

const (
	CapabilityPull          Capability = "pull"
	CapabilityPush          Capability = "push"
	CapabilityReadHistory   Capability = "read_history"
	CapabilityDeleteHistory Capability = "delete_history"
	CapabilityManage        Capability = "manage"
)

// Permissions mirrors the flags exposed by the official Lumina SDK.
type Permissions struct {
	IsAdmin          bool `json:"is_admin"`
	CanDeleteHistory bool `json:"can_delete_history"`
}

func (p Permissions) Can(capability Capability) bool {
	switch capability {
	case CapabilityPull, CapabilityPush, CapabilityReadHistory:
		return true
	case CapabilityDeleteHistory:
		return p.IsAdmin || p.CanDeleteHistory
	case CapabilityManage:
		return p.IsAdmin
	default:
		return false
	}
}
