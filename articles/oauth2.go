package authentication

import (
	"io"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

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

	GITHUB_CLIENT_ID = os.Getenv("GITHUB_CLIENT_ID")
	GITHUB_CLIENT_SECRET = os.Getenv("GITHUB_CLIENT_SECRET")
	GITHUB_REDIRECT_URL = os.Getenv("GITHUB_REDIRECT_URL")

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

	githubOauthConfig = &oauth2.Config{
		ClientID:     GITHUB_CLIENT_ID,
		ClientSecret: GITHUB_CLIENT_SECRET,
		RedirectURL:  GITHUB_REDIRECT_URL,
		Scopes:       github_scopes,
		Endpoint:     github.Endpoint,
	}
}

func (_ Oauth2AuthenticationHandler) Bind(mux *http.ServeMux) {
	Oauth2Authentication.Init()

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

	mux.HandleFunc("/api/protected-google-oauth2-data", GoogleOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*GoogleUser)
		WriteJsonResponse(w, map[string]interface{}{
			"message": "this is protected data",
			"user":    user,
		})
	}))

	mux.HandleFunc("/api/authentication/login/facebook", func(w http.ResponseWriter, r *http.Request) {
		url := facebookOauthConfig.AuthCodeURL(oauthState)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	mux.HandleFunc("/api/authentication/login/facebook/callback", func(w http.ResponseWriter, r *http.Request) {
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

		token, err := facebookOauthConfig.Exchange(r.Context(), code)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		client := facebookOauthConfig.Client(r.Context(), token)
		resp, err := client.Get("https://graph.facebook.com/v12.0/me?fields=id,name,email,picture")
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to get user info: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var facebookUser FacebookUser
		body, _ := io.ReadAll(resp.Body)
		if err := facebookUser.FromJSON(body); err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to parse user info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := struct {
			User  FacebookUser `json:"user"`
			Token string       `json:"token"`
		}{
			User:  facebookUser,
			Token: token.AccessToken,
		}

		WriteJsonResponse(w, response)
	})

	mux.HandleFunc("/api/protected-facebook-oauth2-data", FacebookOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("facebook_user").(*FacebookUser)
		WriteJsonResponse(w, map[string]interface{}{
			"message": "this is protected data",
			"user":    user,
		})
	}))

	mux.HandleFunc("/api/authentication/login/github", func(w http.ResponseWriter, r *http.Request) {
		url := githubOauthConfig.AuthCodeURL(oauthState)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	mux.HandleFunc("/api/authentication/login/github/callback", func(w http.ResponseWriter, r *http.Request) {
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

		token, err := githubOauthConfig.Exchange(r.Context(), code)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		client := githubOauthConfig.Client(r.Context(), token)
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to get user info: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var githubUser GitHubUser
		body, _ := io.ReadAll(resp.Body)
		if err := githubUser.FromJSON(body); err != nil {
			WriteJsonErrorResponseWithStatus(w, "failed to parse user info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := struct {
			User  GitHubUser `json:"user"`
			Token string     `json:"token"`
		}{
			User:  githubUser,
			Token: token.AccessToken,
		}

		WriteJsonResponse(w, response)
	})

	mux.HandleFunc("/api/protected-github-oauth2-data", GitHubOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("github_user").(*GitHubUser)
		WriteJsonResponse(w, map[string]interface{}{
			"message": "this is protected data",
			"user":    user,
		})
	}))
}
