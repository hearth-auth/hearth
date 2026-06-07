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

// apiUser is the wire shape expected by the SPA's Admin page.
type apiUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
}

// ListUsers handles GET /admin/users.
// Requires admin role (enforced by the route's RBAC middleware).
// Returns the authenticated admin user's profile (userinfo + live role
// resolution) so the demo page renders without system-realm credentials.
func (h *Admin) ListUsers(c *gin.Context) {
	raw, _ := c.Get(middleware.KeyRawToken)
	token, _ := raw.(string)

	// Fetch identity and live role assignments from Hearth.
	info, err := h.client.UserInfo(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch user info from Hearth"})
		return
	}
	perms, err := h.client.Permissions(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch permissions from Hearth"})
		return
	}

	c.JSON(http.StatusOK, []apiUser{{
		ID:          info.Sub,
		Email:       info.Email,
		DisplayName: info.Name,
		Roles:       perms.Roles,
	}})
}
