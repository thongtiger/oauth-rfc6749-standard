package handle_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thongtiger/oauth-rfc6749-standard/handle"

	"github.com/labstack/echo"
	"github.com/stretchr/testify/assert"
)

const (
	userJSON        = `{"grant_type":"password","username":"joe","password":"password"}`
	userInvalidJSON = `{"grant_type":"fail","username":"joe","password":"password"}`
)

var (
	client_id, access_token, refresh_token, token_type string
	expires_in                                         int64
	scope                                              []string
)

func TestLoginSuccess(t *testing.T) {
	t.Run("it should return httpCode 200", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// mock
		h := handle.TokenHandle(c)
		// Assertions
		if assert.NoError(t, h) {
			assert.Equal(t, http.StatusOK, rec.Code)
			// assert.Equal(t, userJSON, rec.Body.String())
		}
	})

}
func TestLoginFail(t *testing.T) {
	t.Run("it should return httpCode 401", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userInvalidJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// mock
		h := handle.TokenHandle(c)
		// Assertions
		if assert.NoError(t, h) {
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			if status := rec.Code; status != http.StatusUnauthorized {
				t.Errorf("wrong code: got %v want %v", status, http.StatusOK)
			}

		}
	})
}

func TestRefreshToken(t *testing.T) {
	t.Run("it should return httpCode 401", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userInvalidJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// mock
		h := handle.TokenHandle(c)
		// Assertions
		if assert.NoError(t, h) {
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			if status := rec.Code; status != http.StatusUnauthorized {
				t.Errorf("wrong code: got %v want %v", status, http.StatusOK)
			}

		}
	})
}
