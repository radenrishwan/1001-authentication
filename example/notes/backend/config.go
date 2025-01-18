package notes

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

func NewDatabase(context context.Context) *pgx.Conn {
	dbUrl := os.Getenv("DATABASE_URL")

	if dbUrl == "" {
		log.Fatalln("You need to set database url using env variable DATABASE_URL")
	}

	conn, err := pgx.Connect(context, dbUrl)
	if err != nil {
		log.Fatalln("can't connect to database, make sure your database is running and the url is correct. Error:", err)
	}

	return conn
}
