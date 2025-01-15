package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	GOOGLE_CLIENT_ID     = flag.String("GOOGLE_CLIENT_ID", os.Getenv("GOOGLE_CLIENT_ID"), "Google Client ID")
	GOOGLE_CLIENT_SECRET = flag.String("GOOGLE_CLIENT_SECRET", os.Getenv("GOOGLE_CLIENT_SECRET"), "Google Client Secret")
	GOOGLE_REDIRECT_URL  = flag.String("GOOGLE_REDIRECT_URL", os.Getenv("GOOGLE_REDIRECT_URL"), "Redirect URL")

	oauthState = "random" // TODO: change later
)

var oauthConfig = &oauth2.Config{
	ClientID:     *GOOGLE_CLIENT_ID,
	ClientSecret: *GOOGLE_CLIENT_SECRET,
	RedirectURL:  *GOOGLE_REDIRECT_URL,
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
	Endpoint: google.Endpoint,
}

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

type Oauth2AuthenticationType struct{}

var Oauth2Authentication = Oauth2AuthenticationType{}

func (_ Oauth2AuthenticationType) VerifyUser(r *http.Request) (*GoogleUser, error) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimSpace(authHeader[7:])

	token := &oauth2.Token{
		AccessToken: tokenString,
		TokenType:   "Bearer",
	}

	client := oauthConfig.Client(r.Context(), token)
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

func (_ Oauth2AuthenticationType) Oauth2Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			WriteJsonErrorResponseWithStatus(w, "authorization is empty", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			WriteJsonErrorResponseWithStatus(w, "unsupported auth method", http.StatusUnauthorized)
			return
		}

		user, err := Oauth2Authentication.VerifyUser(r)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// store the user in the context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
