package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
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

var (
	FACEBOOK_CLIENT_ID     string
	FACEBOOK_CLIENT_SECRET string
	FACEBOOK_REDIRECT_URL  string
	facebook_scopes        = []string{} // TODO: add later
)

var googleOauthConfig = &oauth2.Config{}

var facebookOauthConfig = &oauth2.Config{}

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

type Oauth2AuthenticationHandler struct{}

func NewOauth2AuthenticationHandler() Oauth2AuthenticationHandler {
	return Oauth2AuthenticationHandler{}
}

// init all environment variables
func (_ Oauth2AuthenticationType) Init() {
	GOOGLE_CLIENT_ID = os.Getenv("GOOGLE_CLIENT_ID")
	GOOGLE_CLIENT_SECRET = os.Getenv("GOOGLE_CLIENT_SECRET")
	GOOGLE_REDIRECT_URL = os.Getenv("GOOGLE_REDIRECT_URL")

	FACEBOOK_CLIENT_ID = os.Getenv("FACEBOOK_CLIENT_ID")
	FACEBOOK_CLIENT_SECRET = os.Getenv("FACEBOOK_CLIENT_SECRET")
	FACEBOOK_REDIRECT_URL = os.Getenv("FACEBOOK_REDIRECT_URL")

	googleOauthConfig = &oauth2.Config{
		ClientID:     GOOGLE_CLIENT_ID,
		ClientSecret: GOOGLE_CLIENT_SECRET,
		RedirectURL:  GOOGLE_REDIRECT_URL,
		Scopes:       google_scopes,
		Endpoint:     google.Endpoint,
	}

	facebookOauthConfig = &oauth2.Config{
		ClientID:     FACEBOOK_CLIENT_ID,
		ClientSecret: FACEBOOK_CLIENT_SECRET,
		RedirectURL:  FACEBOOK_REDIRECT_URL,
		Scopes:       facebook_scopes,
		Endpoint:     facebook.Endpoint,
	}
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
		auth := r.Header.Get("Authorization")
		if auth == "" {
			WriteJsonErrorResponseWithStatus(w, "authorization is empty", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			WriteJsonErrorResponseWithStatus(w, "unsupported auth method", http.StatusUnauthorized)
			return
		}

		user, err := Oauth2Authentication.GoogleVerifyUser(r)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// store the user in the context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (_ Oauth2AuthenticationHandler) Bind(mux *http.ServeMux) {
	Oauth2Authentication.Init()

	// print google client data
	fmt.Println("Google Client ID: ", GOOGLE_CLIENT_ID)
	fmt.Println("Google Client Secret: ", GOOGLE_CLIENT_SECRET)
	fmt.Println("Google Redirect URL: ", GOOGLE_REDIRECT_URL)
	fmt.Println("Google Scopes: ", google_scopes)

	mux.HandleFunc("/api/authentication/login/google", func(w http.ResponseWriter, r *http.Request) {
		url := googleOauthConfig.AuthCodeURL(oauthState)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	mux.HandleFunc("/api/authentication/login/google/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state != oauthState {
			WriteJsonErrorResponseWithStatus(w, "invalid oauth state", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			WriteJsonErrorResponseWithStatus(w, "code not found", http.StatusBadRequest)
			return
		}

		token, err := googleOauthConfig.Exchange(r.Context(), code)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		client := googleOauthConfig.Client(r.Context(), token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to get user info: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var googleUser GoogleUser
		body, _ := io.ReadAll(resp.Body)
		if err := googleUser.FromJSON(body); err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to parse user info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := struct {
			User  GoogleUser `json:"user"`
			Token string     `json:"token"`
		}{
			User:  googleUser,
			Token: token.AccessToken,
		}

		WriteJsonResponse(w, response)
	})

	// handle that protected data by google oauth2

	mux.HandleFunc("/api/protected-google-oauth2-data", GoogleOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*GoogleUser)
		WriteJsonResponse(w, map[string]interface{}{
			"message": "this is protected data",
			"user":    user,
		})
	}))
}
