package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	authentication "github.com/radenrishwan/1001-authentication"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

 fmt.Println("From main:", os.Getenv("GOOGLE_CLIENT_ID"))
    fmt.Println("From main:", os.Getenv("GOOGLE_CLIENT_SECRET"))
    fmt.Println("From main:", os.Getenv("GOOGLE_REDIRECT_URL"))

	mux := http.NewServeMux()

	// create new basic authentication handler
	basicAuthHandler := authentication.NewBasicAuthenticationHandler()
	basicAuthHandler.Bind(mux)

	// create new jwt authentication handler
	jwtAuthHandler := authentication.NewJWTAuthenticationHandler()
	jwtAuthHandler.Bind(mux)

	// create new oauth2 authentication handler
	oauth2AuthHandler := authentication.NewOauth2AuthenticationHandler()
	oauth2AuthHandler.Bind(mux)

	http.ListenAndServe(":8080", mux)
}
