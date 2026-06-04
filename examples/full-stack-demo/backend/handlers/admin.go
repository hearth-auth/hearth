package handlers

import (
	"net/http"

	"github.com/anthropics/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

// Admin handles administrative endpoints backed by the Hearth Admin API.
type Admin struct {
	client *hearth.Client
}

// NewAdmin creates an Admin handler backed by the given Hearth client.
func NewAdmin(c *hearth.Client) *Admin {
	return &Admin{client: c}
}

// ListUsers handles GET /admin/users — proxies the Hearth Admin user list.
// Requires admin role (enforced by the route's RBAC middleware).
func (h *Admin) ListUsers(c *gin.Context) {
	raw, _ := c.Get(middleware.KeyRawToken)
	token, _ := raw.(string)

	// The caller's token is forwarded to the Hearth Admin API.
	// Hearth enforces that the bearer must hold the admin role server-side.
	page, err := h.client.Admin(token).ListUsers(c.Request.Context(), hearth.ListOptions{})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch users from Hearth"})
		return
	}
	c.JSON(http.StatusOK, page)
}
