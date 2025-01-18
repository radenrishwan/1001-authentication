package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/radenrishwan/notes"
	"github.com/radenrishwan/notes/authentication"
	"github.com/radenrishwan/notes/note"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db := notes.NewDatabase(context.Background())
	mux := http.NewServeMux()

	mux.HandleFunc("GET /hc", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// register auth handler
	authHandler := authentication.NewOauth2AuthenticationHandler()
	authHandler.Bind(mux)

	// register notes handler
	notesHandler := note.NewNotesHandler(db)
	notesHandler.Bind(mux)

	if os.Getenv("PORT") == "" {
		log.Fatalln("PORT is not set!")
	}

	addr := ":" + os.Getenv("PORT")
	log.Printf("Server starting on %s", addr)

	err = http.ListenAndServe(addr, mux)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
