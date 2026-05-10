package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ashokdan/guardrails/internal/models"
)

const authHeader = "X-Guardrail-Auth-Key"

func AuthMiddleware(expectedKey string) gin.HandlerFunc {
	expected := []byte(expectedKey)
	return func(c *gin.Context) {
		provided := c.GetHeader(authHeader)
		if provided == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth header"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(provided), expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid auth header"})
			return
		}

		clientID := c.GetHeader("X-Client-Id")
		if clientID == "" {
			clientID = "litellm"
		}
		c.Set("authContext", &models.AuthContext{ClientID: clientID})
		c.Next()
	}
}

func GetAuthContext(c *gin.Context) *models.AuthContext {
	v, ok := c.Get("authContext")
	if !ok {
		panic("AuthContext missing from gin context")
	}
	return v.(*models.AuthContext)
}
