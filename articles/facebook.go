package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

var (
	FACEBOOK_CLIENT_ID     string
	FACEBOOK_CLIENT_SECRET string
	FACEBOOK_REDIRECT_URL  string
	facebook_scopes        = []string{
		"email",
		"public_profile",
	}
)

var facebookOauthConfig = &oauth2.Config{}

type FacebookUser struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

func (u *FacebookUser) ToJSON() ([]byte, error) {
	return json.Marshal(u)
}

func (u *FacebookUser) FromJSON(data []byte) error {
	return json.Unmarshal(data, u)
}

func (_ Oauth2AuthenticationType) FacebookVerifyUser(r *http.Request) (*FacebookUser, error) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimSpace(authHeader[7:])

	token := &oauth2.Token{
		AccessToken: tokenString,
		TokenType:   "Bearer",
	}

	client := facebookOauthConfig.Client(r.Context(), token)
	resp, err := client.Get("https://graph.facebook.com/v12.0/me?fields=id,name,email,picture")
	if err != nil {
		return nil, errors.New("Failed to get user info: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Invalid or expired token")
	}

	var facebookUser FacebookUser
	body, _ := io.ReadAll(resp.Body)
	if err := facebookUser.FromJSON(body); err != nil {
		return nil, errors.New("Failed to decode user info: " + err.Error())
	}

	return &facebookUser, nil
}

func FacebookOauth2Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			WriteJsonErrorResponseWithStatus(w, "authorization is empty", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			WriteJsonErrorResponseWithStatus(w, "unsupported auth method", http.StatusUnauthorized)
			return
		}

		user, err := Oauth2Authentication.FacebookVerifyUser(r)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "facebook_user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
