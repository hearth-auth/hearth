// Package store provides a simple in-memory notes store for the demo.
package store

import (
	"fmt"
	"sync"
	"time"
)

// Note is a single user note.
type Note struct {
	ID        string `json:"id"`
	Body      string `json:"body"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// Notes is a thread-safe in-memory store.
type Notes struct {
	mu      sync.RWMutex
	records []*Note
	nextID  int
}

// NewNotes returns an empty Notes store pre-populated with a sample note.
func NewNotes() *Notes {
	n := &Notes{}
	n.Create("Welcome to the Hearth full-stack demo!")
	n.Create("Editors can create and update notes. Admins can delete them.")
	return n
}

// List returns a snapshot of all notes.
func (n *Notes) List() []*Note {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]*Note, len(n.records))
	copy(out, n.records)
	return out
}

// Create appends a new note and returns it.
func (n *Notes) Create(body string) *Note {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextID++
	note := &Note{
		ID:        fmt.Sprintf("%d", n.nextID),
		Body:      body,
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}
	n.records = append(n.records, note)
	return note
}

// Update replaces the body of the note with the given ID.
func (n *Notes) Update(id, body string) (*Note, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, note := range n.records {
		if note.ID == id {
			note.Body = body
			note.UpdatedAt = time.Now().Unix()
			return note, true
		}
	}
	return nil, false
}

// Delete removes the note with the given ID.
func (n *Notes) Delete(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, note := range n.records {
		if note.ID == id {
			n.records = append(n.records[:i], n.records[i+1:]...)
			return true
		}
	}
	return false
}
