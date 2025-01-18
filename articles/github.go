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
	GITHUB_CLIENT_ID     string
	GITHUB_CLIENT_SECRET string
	GITHUB_REDIRECT_URL  string
	github_scopes        = []string{
		"user:email",
		"read:user",
	}
)

var githubOauthConfig = &oauth2.Config{}

type GitHubUser struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (u *GitHubUser) ToJSON() ([]byte, error) {
	return json.Marshal(u)
}

func (u *GitHubUser) FromJSON(data []byte) error {
	return json.Unmarshal(data, u)
}

func (_ Oauth2AuthenticationType) GitHubVerifyUser(r *http.Request) (*GitHubUser, error) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimSpace(authHeader[7:])

	token := &oauth2.Token{
		AccessToken: tokenString,
		TokenType:   "Bearer",
	}

	client := githubOauthConfig.Client(r.Context(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, errors.New("Failed to get user info: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Invalid or expired token")
	}

	var githubUser GitHubUser
	body, _ := io.ReadAll(resp.Body)
	if err := githubUser.FromJSON(body); err != nil {
		return nil, errors.New("Failed to decode user info: " + err.Error())
	}

	return &githubUser, nil
}

func GitHubOauth2Middleware(next http.HandlerFunc) http.HandlerFunc {
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

		user, err := Oauth2Authentication.GitHubVerifyUser(r)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "github_user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
