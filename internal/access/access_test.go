package access

import "testing"

func TestOfficialPermissionFlags(t *testing.T) {
	regular := Permissions{}
	if !regular.Can(CapabilityPull) || !regular.Can(CapabilityPush) ||
		!regular.Can(CapabilityReadHistory) {
		t.Fatal("regular Lumina user cannot use metadata operations")
	}
	if regular.Can(CapabilityDeleteHistory) || regular.Can(CapabilityManage) {
		t.Fatal("regular Lumina user received administrative permissions")
	}

	historyOperator := Permissions{CanDeleteHistory: true}
	if !historyOperator.Can(CapabilityDeleteHistory) || historyOperator.Can(CapabilityManage) {
		t.Fatal("history permission did not remain independent from administrator status")
	}

	admin := Permissions{IsAdmin: true}
	if !admin.Can(CapabilityDeleteHistory) || !admin.Can(CapabilityManage) {
		t.Fatal("administrator did not receive official administrative permissions")
	}
	if admin.Can(Capability("unknown")) {
		t.Fatal("unknown capability was granted")
	}
}
