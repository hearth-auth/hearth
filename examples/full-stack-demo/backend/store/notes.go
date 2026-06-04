// Package store provides a thread-safe in-memory note store for the demo.
package store

import (
	"fmt"
	"sync"
	"time"
)

// Note is a simple content item managed by the demo API.
type Note struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	AuthorID  string    `json:"author_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Notes is a thread-safe in-memory store for Note records.
type Notes struct {
	mu    sync.RWMutex
	items map[string]Note
	seq   int
}

// NewNotes returns an empty Notes store.
func NewNotes() *Notes {
	return &Notes{items: make(map[string]Note)}
}

// List returns all notes in unspecified order.
func (s *Notes) List() []Note {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Note, 0, len(s.items))
	for _, n := range s.items {
		out = append(out, n)
	}
	return out
}

// Create inserts a new note and returns it.
func (s *Notes) Create(title, body, authorID string) Note {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	n := Note{
		ID:        fmt.Sprintf("note-%d", s.seq),
		Title:     title,
		Body:      body,
		AuthorID:  authorID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	s.items[n.ID] = n
	return n
}

// Update patches the title and/or body of an existing note.
// Returns the updated note and true, or the zero value and false when not found.
func (s *Notes) Update(id, title, body string) (Note, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.items[id]
	if !ok {
		return Note{}, false
	}
	if title != "" {
		n.Title = title
	}
	if body != "" {
		n.Body = body
	}
	n.UpdatedAt = time.Now().UTC()
	s.items[id] = n
	return n, true
}

// Delete removes a note by ID. Returns true if it existed.
func (s *Notes) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.items[id]
	if !ok {
		return false
	}
	delete(s.items, id)
	return true
}
