package driver

import (
	"database/sql"
	"log"
	"os"

	"github.com/lib/pq"
	"github.com/subosito/gotenv"
)

func GetConnection() *sql.DB {
	gotenv.Load()
	pgUrl, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_ID"))

	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("postgres", pgUrl)

	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	return db
}
