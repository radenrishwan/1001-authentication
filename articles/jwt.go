package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecretKey = []byte("your-secret-key") // move into environment variable

type JWTAuthenticationUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JWTClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type JWTAuthenticationType struct{}

var JWTAuthentication = JWTAuthenticationType{}

type JWTAuthenticationHandler struct{}

func NewJWTAuthenticationHandler() JWTAuthenticationHandler {
	return JWTAuthenticationHandler{}
}

func (_ JWTAuthenticationType) GenerateToken(user JWTAuthenticationUser) (string, error) {
	if user.Username == "" || user.Password == "" {
		return "", errors.New("username or password is empty")
	}

	// generate claims
	claims := JWTClaims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// encode token
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (_ JWTAuthenticationType) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (_ JWTAuthenticationType) ValidateCredentials(user JWTAuthenticationUser) bool {
	// TODO: check user validation on database if you save user data in database
	return true
}

func JWTAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
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

		tokenString := strings.TrimPrefix(auth, "Bearer ")

		// validate token
		claims, err := JWTAuthentication.ValidateToken(tokenString)
		if err != nil {
			WriteJsonErrorResponseWithStatus(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// add claims to context
		ctx := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(ctx)

		next(w, r)
	}
}

func (h JWTAuthenticationHandler) Bind(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/authentication/login/jwt", func(w http.ResponseWriter, r *http.Request) {
		var user JWTAuthenticationUser
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			WriteJsonErrorResponse(w, "error decoding request body")
			return
		}

		if user.Username == "" || user.Password == "" {
			WriteJsonErrorResponse(w, "username or password is empty")
			return
		}

		if ok := JWTAuthentication.ValidateCredentials(user); !ok {
			WriteJsonErrorResponseWithStatus(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		// generate new token
		token, err := JWTAuthentication.GenerateToken(user)
		if err != nil {
			WriteJsonErrorResponse(w, "error generating token")
			return
		}

		WriteJsonResponse(w, map[string]any{
			"message": "user has been logged in",
			"token":   token,
		})
	})

	mux.HandleFunc("/api/protected-jwt-data", JWTAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("claims").(*JWTClaims)

		WriteJsonResponse(w, map[string]any{
			"message": "this is protected data accessed with JWT",
			"user":    user,
		})
	}))
}
