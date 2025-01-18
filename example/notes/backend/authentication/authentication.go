package authentication

import (
	"io"
	"net/http"
	"os"

	"github.com/radenrishwan/notes"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Oauth2AuthenticationType struct{}

var Oauth2Authentication = Oauth2AuthenticationType{}

type Oauth2AuthenticationHandler struct{}

func NewOauth2AuthenticationHandler() Oauth2AuthenticationHandler {
	return Oauth2AuthenticationHandler{}
}

func (_ Oauth2AuthenticationType) Init() {
	GOOGLE_CLIENT_ID = os.Getenv("GOOGLE_CLIENT_ID")
	GOOGLE_CLIENT_SECRET = os.Getenv("GOOGLE_CLIENT_SECRET")
	GOOGLE_REDIRECT_URL = os.Getenv("GOOGLE_REDIRECT_URL")

	googleOauthConfig = &oauth2.Config{
		ClientID:     GOOGLE_CLIENT_ID,
		ClientSecret: GOOGLE_CLIENT_SECRET,
		RedirectURL:  GOOGLE_REDIRECT_URL,
		Scopes:       google_scopes,
		Endpoint:     google.Endpoint,
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
			notes.WriteJsonErrorResponseWithStatus(w, "invalid oauth state", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			notes.WriteJsonErrorResponseWithStatus(w, "code not found", http.StatusBadRequest)
			return
		}

		token, err := googleOauthConfig.Exchange(r.Context(), code)
		if err != nil {
			notes.WriteJsonErrorResponseWithStatus(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		client := googleOauthConfig.Client(r.Context(), token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			notes.WriteJsonErrorResponseWithStatus(w, "failed to get user info: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var googleUser GoogleUser
		body, _ := io.ReadAll(resp.Body)
		if err := googleUser.FromJSON(body); err != nil {
			notes.WriteJsonErrorResponseWithStatus(w, "failed to parse user info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := struct {
			User  GoogleUser `json:"user"`
			Token string     `json:"token"`
		}{
			User:  googleUser,
			Token: token.AccessToken,
		}

		notes.WriteJsonResponse(w, response)
	})

}
