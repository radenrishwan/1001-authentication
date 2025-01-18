package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/radenrishwan/notes"
	"golang.org/x/oauth2"
)

var (
	GOOGLE_CLIENT_ID     string
	GOOGLE_CLIENT_SECRET string
	GOOGLE_REDIRECT_URL  string
	google_scopes        = []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	} // references: https://developers.google.com/identity/protocols/oauth2/scopes

	oauthState = "random" // TODO: change this to random string later
)

var googleOauthConfig = &oauth2.Config{}

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (u *GoogleUser) ToJSON() ([]byte, error) {
	return json.Marshal(u)
}

func (u *GoogleUser) FromJSON(data []byte) error {
	return json.Unmarshal(data, u)
}

func (_ Oauth2AuthenticationType) GoogleVerifyUser(r *http.Request) (*GoogleUser, error) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimSpace(authHeader[7:])

	token := &oauth2.Token{
		AccessToken: tokenString,
		TokenType:   "Bearer",
	}

	client := googleOauthConfig.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, errors.New("Failed to get user info: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Invalid or expired token")
	}

	var googleUser GoogleUser
	body, _ := io.ReadAll(resp.Body)
	if err := googleUser.FromJSON(body); err != nil {
		return nil, errors.New("Failed to decode user info: " + err.Error())
	}

	return &googleUser, nil
}

func GoogleOauth2Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("entering oauth2 middleware...")

		auth := r.Header.Get("Authorization")
		if auth == "" {
			notes.WriteJsonErrorResponseWithStatus(w, "authorization is empty", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			notes.WriteJsonErrorResponseWithStatus(w, "unsupported auth method", http.StatusUnauthorized)
			return
		}

		user, err := Oauth2Authentication.GoogleVerifyUser(r)
		if err != nil {
			notes.WriteJsonErrorResponseWithStatus(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// store the user in the context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
