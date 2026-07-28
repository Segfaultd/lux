package session

import (
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segfaultd/lux/internal/access"
)

var ErrNotFound = errors.New("session not found")

type Session struct {
	ID               uint64      `json:"id"`
	AccountID        int64       `json:"account_id"`
	Username         string      `json:"username"`
	Role             access.Role `json:"role"`
	RemoteAddress    string      `json:"remote_address"`
	Hostname         string      `json:"hostname,omitempty"`
	ProtocolVersion  uint32      `json:"protocol_version"`
	ConnectedAt      time.Time   `json:"connected_at"`
	LastActivityAt   time.Time   `json:"last_activity_at"`
	CurrentOperation string      `json:"current_operation,omitempty"`
	LastOperation    string      `json:"last_operation,omitempty"`
	Requests         uint64      `json:"requests"`
	Errors           uint64      `json:"errors"`
	BytesRead        uint64      `json:"bytes_read"`
	BytesWritten     uint64      `json:"bytes_written"`
}

type Identity struct {
	AccountID       int64
	Username        string
	Role            access.Role
	RemoteAddress   string
	ProtocolVersion uint32
}

type Connection struct {
	net.Conn
	bytesRead    atomic.Uint64
	bytesWritten atomic.Uint64
}

func Track(conn net.Conn) *Connection {
	if tracked, ok := conn.(*Connection); ok {
		return tracked
	}
	return &Connection{Conn: conn}
}

func (c *Connection) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	c.bytesRead.Add(uint64(n))
	return n, err
}

func (c *Connection) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	c.bytesWritten.Add(uint64(n))
	return n, err
}

func (c *Connection) totals() (uint64, uint64) {
	return c.bytesRead.Load(), c.bytesWritten.Load()
}

type entry struct {
	session Session
	conn    *Connection
}

type Registry struct {
	mu       sync.RWMutex
	nextID   uint64
	sessions map[uint64]*entry
	now      func() time.Time
}

func NewRegistry() *Registry {
	return &Registry{sessions: make(map[uint64]*entry), now: time.Now}
}

func (r *Registry) Register(identity Identity, conn *Connection) Session {
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	current := Session{
		ID:              r.nextID,
		AccountID:       identity.AccountID,
		Username:        identity.Username,
		Role:            identity.Role,
		RemoteAddress:   identity.RemoteAddress,
		ProtocolVersion: identity.ProtocolVersion,
		ConnectedAt:     now,
		LastActivityAt:  now,
	}
	r.sessions[current.ID] = &entry{session: current, conn: conn}
	return current
}

func (r *Registry) Unregister(id uint64) {
	r.mu.Lock()
	delete(r.sessions, id)
	r.mu.Unlock()
}

func (r *Registry) StartRequest(id uint64, operation string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.sessions[id]; current != nil {
		current.session.CurrentOperation = operation
		current.session.LastActivityAt = r.now().UTC()
		current.session.Requests++
	}
}

func (r *Registry) FinishRequest(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.sessions[id]; current != nil {
		current.session.LastOperation = current.session.CurrentOperation
		current.session.CurrentOperation = ""
		current.session.LastActivityAt = r.now().UTC()
	}
}

func (r *Registry) RecordError(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.sessions[id]; current != nil {
		current.session.Errors++
		current.session.LastActivityAt = r.now().UTC()
	}
}

func (r *Registry) SetHostname(id uint64, hostname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.sessions[id]; current != nil {
		current.session.Hostname = hostname
	}
}

func (r *Registry) List() []Session {
	r.mu.RLock()
	sessions := make([]Session, 0, len(r.sessions))
	for _, current := range r.sessions {
		sessions = append(sessions, snapshot(current))
	}
	r.mu.RUnlock()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].ID < sessions[j].ID })
	return sessions
}

func (r *Registry) Get(id uint64) (Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current := r.sessions[id]
	if current == nil {
		return Session{}, ErrNotFound
	}
	return snapshot(current), nil
}

func (r *Registry) Terminate(id uint64) (Session, error) {
	r.mu.Lock()
	current := r.sessions[id]
	if current == nil {
		r.mu.Unlock()
		return Session{}, ErrNotFound
	}
	result := snapshot(current)
	conn := current.conn
	delete(r.sessions, id)
	r.mu.Unlock()
	return result, conn.Close()
}

func (r *Registry) TerminateAccount(accountID int64) int {
	return r.terminateMatching(func(current Session) bool {
		return current.AccountID == accountID
	})
}

func (r *Registry) TerminateUsername(username string) int {
	return r.terminateMatching(func(current Session) bool {
		return strings.EqualFold(current.Username, username)
	})
}

func (r *Registry) terminateMatching(matches func(Session) bool) int {
	r.mu.Lock()
	var connections []*Connection
	for id, current := range r.sessions {
		if matches(current.session) {
			connections = append(connections, current.conn)
			delete(r.sessions, id)
		}
	}
	r.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return len(connections)
}

func snapshot(current *entry) Session {
	result := current.session
	result.BytesRead, result.BytesWritten = current.conn.totals()
	return result
}
