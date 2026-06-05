// Package handlers contains HTTP handler implementations for the demo API.
package handlers

import (
	"net/http"

	"github.com/anthropics/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/store"
	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

// Notes handles CRUD operations on the in-memory note store.
type Notes struct {
	store  *store.Notes
	client *hearth.Client
}

// NewNotes creates a Notes handler backed by the given store and Hearth client.
func NewNotes(s *store.Notes, c *hearth.Client) *Notes {
	return &Notes{store: s, client: c}
}

type createNoteReq struct {
	Title   string `json:"title" binding:"required"`
	Content string `json:"content"`
}

type updateNoteReq struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

// List handles GET /notes — returns all notes. Requires any authenticated user.
func (h *Notes) List(c *gin.Context) {
	c.JSON(http.StatusOK, h.store.List())
}

// Create handles POST /notes — creates a note. Requires content.write permission.
func (h *Notes) Create(c *gin.Context) {
	var req createNoteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	raw, _ := c.Get(middleware.KeyRawToken)
	token, _ := raw.(string)

	// Extract subject from JWT claims to tag the note's author.
	var author string
	if claims, err := hearth.ParseClaims(token); err == nil {
		author = claims.Subject()
	}

	note := h.store.Create(req.Title, req.Content, author)
	c.JSON(http.StatusCreated, note)
}

// Update handles PATCH /notes/:id — updates a note. Requires content.write permission.
func (h *Notes) Update(c *gin.Context) {
	var req updateNoteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := c.Param("id")
	note, ok := h.store.Update(id, req.Title, req.Content)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
		return
	}
	c.JSON(http.StatusOK, note)
}

// Delete handles DELETE /notes/:id — deletes a note. Requires admin role.
func (h *Notes) Delete(c *gin.Context) {
	id := c.Param("id")
	if !h.store.Delete(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
		return
	}
	c.Status(http.StatusNoContent)
}
