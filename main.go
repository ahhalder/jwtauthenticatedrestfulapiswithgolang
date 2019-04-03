package main

import (
	"database/sql"
	"log"
	"net/http"

	"./controllers"
	"./driver"
	"github.com/subosito/gotenv"

	"github.com/gorilla/mux"
)

var db *sql.DB

func main() {

	controler := controllers.Controller{}

	gotenv.Load()
	db = driver.GetConnection()
	r := mux.NewRouter()
	r.HandleFunc("/signup", controler.Signup(db)).Methods("POST")
	r.HandleFunc("/login", controler.Login(db)).Methods("POST")
	r.HandleFunc("/protected", controler.TokenVerifyMiddleWare(controler.ProtectedEndpoint())).Methods("GET")

	log.Println("Listenting on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", r))
}
