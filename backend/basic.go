package authentication

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type BasicAuthenticationUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type BasicAuthenticationType struct{}

var BasicAuthentication = BasicAuthenticationType{}

type BasicAuthenticationHandler struct{}

func NewBasicAuthenticationHandler() BasicAuthenticationHandler {
	return BasicAuthenticationHandler{}
}

func (_ BasicAuthenticationType) GenerateCredentials(user BasicAuthenticationUser) (string, error) {
	// check if username or password is empty
	if user.Username == "" || user.Password == "" {
		return "", errors.New("username or password is empty")
	}

	// decode username and password
	data := user.Username + ":" + user.Password
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	return string(encoded), nil
}

func (_ BasicAuthenticationType) DecodeCredentials(raw []byte) (BasicAuthenticationUser, error) {
	// decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return BasicAuthenticationUser{}, err
	}

	// splitting username and password
	credentials := strings.Split(string(decoded), ":")
	if len(credentials) != 2 {
		return BasicAuthenticationUser{}, errors.New("invalid credentials format")
	}

	return BasicAuthenticationUser{
		Username: credentials[0],
		Password: credentials[1],
	}, nil
}

func (_ BasicAuthenticationType) ValidateCredentials(user BasicAuthenticationUser) bool {
	return true
}

func BasicAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get authorization from header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// return status unauthorization if not set
			WriteJsonErrorResponseWithStatus(w, "authorization is empty", http.StatusUnauthorized)
			return
		}

		// check if request using basic authentication
		if !strings.HasPrefix(auth, "Basic ") {
			WriteJsonErrorResponseWithStatus(w, "unsupported auth method", http.StatusUnauthorized)
			return
		}

		// decode credentials
		credentials := strings.TrimPrefix(auth, "Basic ")
		user, err := BasicAuthentication.DecodeCredentials([]byte(credentials))
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "error credentials format", http.StatusUnauthorized)
			return
		}

		// TODO: finish validate credentials
		if ok := BasicAuthentication.ValidateCredentials(user); !ok {
			WriteJsonErrorResponseWithStatus(w, "wrong credentials", http.StatusUnauthorized)
			return
		}

		// if valid, process the request
		next(w, r)
	}
}

func (h BasicAuthenticationHandler) Bind(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/authentication/login/basic", func(w http.ResponseWriter, r *http.Request) {
		// get username and password from request body
		var user BasicAuthenticationUser
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			WriteJsonErrorResponse(w, "error decoding request body")
			return
		}

		if user.Username == "" || user.Password == "" {
			WriteJsonErrorResponse(w, "username or password is empty")
			return
		}

		e, _ := BasicAuthentication.GenerateCredentials(BasicAuthenticationUser{
			Username: user.Username,
			Password: user.Password,
		})

		WriteJsonResponse(w, map[string]any{
			"message": "user has been logged in",
			"user":    e,
		})
	})

	mux.HandleFunc("/api/protected-data", BasicAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		WriteJsonResponse(w, map[string]any{
			"message": "this is protected data",
		})
	}))
}
