package middleware

import (
	"net/http"

	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

// RequireRole returns a Gin middleware that aborts with 403 when the authenticated
// user's JWT does not contain the given role. Must be chained after Auth.
func RequireRole(client *hearth.Client, role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, _ := c.Get(KeyRawToken)
		token, _ := raw.(string)
		if !client.HasRole(token, role) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":         "forbidden",
				"required_role": role,
			})
			return
		}
		c.Next()
	}
}

// RequirePermission returns a Gin middleware that aborts with 403 when the
// authenticated user's JWT does not contain the given permission.
// Must be chained after Auth.
func RequirePermission(client *hearth.Client, perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, _ := c.Get(KeyRawToken)
		token, _ := raw.(string)
		if !client.HasPermission(token, perm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":               "forbidden",
				"required_permission": perm,
			})
			return
		}
		c.Next()
	}
}
