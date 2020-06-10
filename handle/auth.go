package handle

import (
	"net/http"
	"time"

	"github.com/thongtiger/oauth-rfc6749-standard/auth"
	"github.com/thongtiger/oauth-rfc6749-standard/redis"

	"github.com/labstack/echo"
)

const (
	//accessTokenDuration  = time.Duration(time.Second* 5) // test
	accessTokenDuration  = time.Duration(time.Minute * 30)
	refreshTokenDuration = time.Duration(time.Hour * 1)
)

// TokenHandle route
func TokenHandle(c echo.Context) (err error) {
	body := auth.Oauth2{}
	if err = c.Bind(&body); err != nil {
		return c.JSON(http.StatusUnsupportedMediaType, echo.Map{})
	}
	switch body.GrantType {
	case "password":
		if ok, user := auth.ValidateUser(body.Username, body.Password); ok {
			// generate token
			return GenerateTK(c, user)
		}
	case "refresh_token":
		return RefreshTK(c, body)
	}
	return c.JSON(http.StatusUnauthorized, echo.Map{})
}

// RefreshTK reset token
func RefreshTK(c echo.Context, oauth2 auth.Oauth2) (err error) {
	// validate
	tokenValid, claim := auth.ValidateRefreshToken(oauth2.RefreshToken)
	if !tokenValid {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "bad refresh_token"})
	}
	// exists
	if exist := redis.Exists(claim.ID, oauth2.RefreshToken); !exist {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "refresh_token does not exist or expired"})
	}
	// generate token
	user := auth.User{ID: claim.ID, Username: claim.Username, Role: claim.Role, Scope: claim.Scope}
	return GenerateTK(c, user)
}

//GenerateTK generate response token
func GenerateTK(c echo.Context, user auth.User) (err error) {
	accessToken, err := auth.NewToken(user.ID, user.Username, accessTokenDuration, "access_token", user.Role, user.Scope...)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "can't generate access_token", "err": err.Error()})
	}
	refreshToken, err := auth.NewToken(user.ID, user.Username, refreshTokenDuration, "refresh_token", user.Role, user.Scope...)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "can't generate refresh_token"})
	}
	return c.JSON(http.StatusOK, echo.Map{
		"client_id":     user.ID,
		"username":      user.Username,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "bearer",
		"expires_in":    accessTokenDuration.Milliseconds(), // for javascript : setInterval
		"scope":         user.Scope,
		"role":          user.Role,
	})
}

// LogoutHandle : delete claimID in redis
func LogoutHandle(c echo.Context) (err error) {
	claim := auth.TokenInfo(c)
	if claim == nil {
		return c.JSON(http.StatusOK, echo.Map{"message": "logout fail"})
	}
	if err = redis.DelClientID(claim.ID); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "redis can't delete key"})
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "logout succeeded"})
}
