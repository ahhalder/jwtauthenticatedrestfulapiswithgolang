package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/davecgh/go-spew/spew"

	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Email    string
	Password string
}

type JWT struct {
	Token string
}

type Error struct {
	Message string
}

var db *sql.DB

func main() {

	pgUrl, err := pq.ParseURL("postgres://nlifupfj:nuUlrESyDMVc3yFEj3mePAQf7h7YyYJ1@manny.db.elephantsql.com:5432/nlifupfj")

	if err != nil {
		log.Fatal(err)
	}
	db, err = sql.Open("postgres", pgUrl)

	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")

	log.Println("Listenting on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", r))
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)

}

func response(w http.ResponseWriter, err Error, status int) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(err)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)
	spew.Dump(user)
	if user.Email == "" {
		error.Message = "Missing Email"
		response(w, error, http.StatusBadRequest)
		return
	}

	if user.Password == "" {
		error.Message = "Missing password"
		response(w, error, http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}
	user.Password = string(hash)
	stmt := "insert into users (email, password) values($1, $2) RETURNING id"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "Server Error."
		response(w, error, http.StatusInternalServerError)
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

	w.Write([]byte("Successuffuly Called Sign UP"))
}

func generateToken(user User) (string, error) {
	secret := "Secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	var jwt JWT
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Missing email"
		response(w, error, http.StatusBadRequest)
		return
	}

	if user.Password == "" {
		error.Message = "Missing password"
		response(w, error, http.StatusBadRequest)
		return
	}

	password := user.Password

	row := db.QueryRow("select * from users where email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "User Does not exixt"
			response(w, error, http.StatusBadRequest)
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		log.Fatal(err)
		error.Message = "invalid Password"
		response(w, error, http.StatusBadRequest)
	}

	spew.Print("suplied password", password)

	token, err := generateToken(user)

	if err != nil {
		log.Fatal(nil)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token
	responseJSON(w, jwt)
	spew.Print(token)

	w.Write([]byte("Successuffuly Called log in"))
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint Invoked")
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was a error")
				}
				return []byte("secret"), nil
			})
			if err != nil {
				errorObject.Message = err.Error()
				response(w, errorObject, http.StatusUnauthorized)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = err.Error()
				response(w, errorObject, http.StatusUnauthorized)
				return
			}
		} else {
			errorObject.Message = "Invalid token"
			response(w, errorObject, http.StatusUnauthorized)
		}
	})
}
