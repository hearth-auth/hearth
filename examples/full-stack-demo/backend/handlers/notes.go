package handlers

import (
	"net/http"

	"github.com/anthropics/hearth/examples/full-stack-demo/backend/store"
	"github.com/gin-gonic/gin"
)

// ListNotes returns all notes visible to the authenticated user.
func ListNotes(notes *store.Notes) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, notes.List())
	}
}

// CreateNote adds a new note (editor+ only — enforced by middleware).
func CreateNote(notes *store.Notes) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Body string `json:"body" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		note := notes.Create(req.Body)
		c.JSON(http.StatusCreated, note)
	}
}

// UpdateNote edits the body of an existing note (editor+ only).
func UpdateNote(notes *store.Notes) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Body string `json:"body" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		note, ok := notes.Update(c.Param("id"), req.Body)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
			return
		}
		c.JSON(http.StatusOK, note)
	}
}

// DeleteNote removes a note by ID (admin only — enforced by middleware).
func DeleteNote(notes *store.Notes) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !notes.Delete(c.Param("id")) {
			c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}
