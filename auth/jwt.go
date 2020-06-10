package auth

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/thongtiger/oauth-rfc6749-standard/redis"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var secretJWT = "secret" // default

// ValidateUser validates credentials of a potential user
func ValidateUser(username, password string) (bool, User) {
	if username == "joe" && password == "password" {
		return true, User{
			ID: "6789",
			// Name:     "ioe",
			Username: "ioe",
			Role:     "emp",
			Scope:    []string{"1", "2"},
		}
	}
	return false, User{}
}
func ValidateRefreshToken(tokenString string) (bool, *TokenClaim) {
	if val, ok := os.LookupEnv("JWT_KEY"); ok {
		secretJWT = strings.TrimSpace(val)
	}
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaim{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretJWT), nil
	})
	if err != nil {
		return false, nil
	}
	if claims, ok := token.Claims.(*TokenClaim); ok && token.Valid {
		log.Printf("%v %v", claims.ID, claims.StandardClaims.ExpiresAt)
		return true, claims

	}
	return false, nil

}

func JWTMiddleware() echo.MiddlewareFunc {
	if val, ok := os.LookupEnv("JWT_KEY"); ok {
		secretJWT = strings.TrimSpace(val)
	}
	return middleware.JWTWithConfig(middleware.JWTConfig{
		Claims:     &TokenClaim{},
		SigningKey: []byte(secretJWT),
		ErrorHandler: func(err error) error {
			return echo.ErrUnauthorized
		},
		Skipper: func(c echo.Context) bool {
			// Skip authentication for and signup login requests
			if c.Path() == "/login" || c.Path() == "/signup" {
				return true
			}
			return false
		},
	}) //echo.HandlerFunc
}

func AcceptedRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user").(*jwt.Token)
			claims := user.Claims.(*TokenClaim)

			for _, checkrole := range roles {
				if checkrole == claims.Role {
					return next(c)
				}
			}
			return c.JSON(http.StatusForbidden, echo.Map{"message": "Access Denied"})
		}
	}
}

func NewToken(id, username string, expiresIn time.Duration, tokenType string, role string, scope ...string) (string, error) {
	if val, ok := os.LookupEnv("JWT_KEY"); ok {
		secretJWT = strings.TrimSpace(val)
	}
	now := time.Now()
	claims := &TokenClaim{
		id,
		username,
		tokenType,
		role,
		scope,
		jwt.StandardClaims{
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(expiresIn).Unix(),
		}}
	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Generate encoded token and send it as response.

	t, err := token.SignedString([]byte(secretJWT))

	if tokenType == "refresh_token" {
		if _, err := redis.SetRefreshToken(id, t, expiresIn); err != nil {
			return "", err
		}
	}

	return t, err
}
func TokenInfo(c echo.Context) *TokenClaim {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*TokenClaim)
	// strconv.Itoa(claims.ID)
	return claims
}
