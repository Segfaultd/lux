package session

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/segfaultd/lux/internal/access"
)

func TestTrackedConnectionCountsTraffic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tracked := Track(server)
	if Track(tracked) != tracked {
		t.Fatal("tracking an existing tracked connection created a wrapper")
	}
	done := make(chan error, 1)
	go func() {
		if _, err := client.Write([]byte("request")); err != nil {
			done <- err
			return
		}
		response := make([]byte, 8)
		_, err := io.ReadFull(client, response)
		done <- err
	}()
	request := make([]byte, 7)
	if _, err := io.ReadFull(tracked, request); err != nil {
		t.Fatal(err)
	}
	if _, err := tracked.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	read, written := tracked.totals()
	if read != 7 || written != 8 {
		t.Fatalf("traffic totals = %d/%d", read, written)
	}
}

func TestRegistryLifecycleAndSnapshots(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.FixedZone("test", 3600))
	registry.now = func() time.Time { return now }
	client, server := net.Pipe()
	defer client.Close()
	tracked := Track(server)
	current := registry.Register(Identity{
		AccountID: 42, Username: "analyst", Role: access.RoleContributor,
		RemoteAddress: "192.0.2.4:12345", ProtocolVersion: 5,
	}, tracked)
	if current.ID != 1 || current.ConnectedAt.Location() != time.UTC {
		t.Fatalf("registered session %#v", current)
	}

	now = now.Add(time.Minute)
	registry.StartRequest(current.ID, "push_metadata")
	registry.RecordError(current.ID)
	registry.SetHostname(current.ID, "workstation")
	active, err := registry.Get(current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active.CurrentOperation != "push_metadata" || active.Requests != 1 ||
		active.Errors != 1 || active.Hostname != "workstation" ||
		!active.LastActivityAt.Equal(now.UTC()) {
		t.Fatalf("active session %#v", active)
	}

	now = now.Add(time.Minute)
	registry.FinishRequest(current.ID)
	active = registry.List()[0]
	if active.CurrentOperation != "" || active.LastOperation != "push_metadata" ||
		!active.LastActivityAt.Equal(now.UTC()) {
		t.Fatalf("finished session %#v", active)
	}
	registry.Unregister(current.ID)
	if len(registry.List()) != 0 {
		t.Fatal("unregistered session remained active")
	}
	if _, err := registry.Get(current.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Get returned %v", err)
	}
	if _, err := registry.Terminate(current.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Terminate returned %v", err)
	}
}

func TestRegistryTermination(t *testing.T) {
	registry := NewRegistry()
	var clients []net.Conn
	for i, accountID := range []int64{7, 7, 8} {
		client, server := net.Pipe()
		clients = append(clients, client)
		current := registry.Register(Identity{
			AccountID: accountID, Username: "user", Role: access.RoleReader,
		}, Track(server))
		if current.ID != uint64(i+1) {
			t.Fatalf("session id %d", current.ID)
		}
	}
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()

	if terminated := registry.TerminateAccount(7); terminated != 2 {
		t.Fatalf("terminated %d sessions", terminated)
	}
	for _, index := range []int{0, 1} {
		if _, err := clients[index].Write([]byte("closed")); err == nil {
			t.Fatalf("client %d remained connected", index)
		}
	}
	if _, err := registry.Terminate(3); err != nil {
		t.Fatal(err)
	}
	if _, err := clients[2].Write([]byte("closed")); err == nil {
		t.Fatal("terminated session remained connected")
	}
	caseClient, caseServer := net.Pipe()
	clients = append(clients, caseClient)
	registry.Register(Identity{
		AccountID: 9, Username: "CaseUser", Role: access.RoleReader,
	}, Track(caseServer))
	if terminated := registry.TerminateUsername("caseuser"); terminated != 1 {
		t.Fatalf("username termination matched %d sessions", terminated)
	}
	if _, err := caseClient.Write([]byte("closed")); err == nil {
		t.Fatal("username-terminated session remained connected")
	}
}
