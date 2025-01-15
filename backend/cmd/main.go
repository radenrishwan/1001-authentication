package main

import (
	"net/http"

	authentication "github.com/radenrishwan/1001-authentication"
)

func main() {
	mux := http.NewServeMux()

	// create new basic authentication handler
	basicAuthHandler := authentication.NewBasicAuthenticationHandler()
	basicAuthHandler.Bind(mux)

	// create new jwt authentication handler
	jwtAuthHandler := authentication.NewJWTAuthenticationHandler()
	jwtAuthHandler.Bind(mux)

	http.ListenAndServe(":8080", mux)
}
