package auth

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type TokenClaim struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Type     string   `json:"type"`
	Role     string   `json:"role"`
	Scope    []string `json:"scope"`
	jwt.StandardClaims
}

type Oauth2 struct {
	Username     string `json:"username,omitempty" form:"username" query:"username"`
	Password     string `json:"password,omitempty" form:"password" query:"password"`
	GrantType    string `json:"grant_type" form:"grant_type" query:"grant_type"`
	RefreshToken string `json:"refresh_token" form:"refresh_token" query:"refresh_token"`
}

type User struct {
	ID       string   `json:"_id"`
	Role     string   `json:"role"`
	Scope    []string `json:"scope"`
	Username string   `json:"username"`
	Password string   `json:"-"`
	// Name           string             `json:"name"`
	CreateTime     time.Time `json:"createTime"`
	LatestLoggedin time.Time `json:"latestLoggedin"`
}

// BcryptCost : Cost
const BcryptCost = 13

// VerifyPassword : checking
func (u *User) VerifyPassword(input string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(input))
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

// HashingPassword : when set to model
func (u *User) HashingPassword() error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(u.Password), BcryptCost)
	if err != nil {
		return err
	}
	u.Password = string(hashed)
	return nil
}
