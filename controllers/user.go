package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"../models"
	"../utills"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func (c Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var error models.Error
		json.NewDecoder(r.Body).Decode(&user)
		spew.Dump(user)
		if user.Email == "" {
			error.Message = "Missing Email"
			utills.Response(w, error, http.StatusBadRequest)
			return
		}

		if user.Password == "" {
			error.Message = "Missing password"
			utills.Response(w, error, http.StatusBadRequest)
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
			utills.Response(w, error, http.StatusInternalServerError)
		}

		user.Password = ""
		w.Header().Set("Content-Type", "application/json")
		utills.ResponseJSON(w, user)

		w.Write([]byte("Successuffuly Called Sign UP"))
	}
}

func (c Controller) Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var error models.Error
		var jwt models.JWT
		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			error.Message = "Missing email"
			utills.Response(w, error, http.StatusBadRequest)
			return
		}

		if user.Password == "" {
			error.Message = "Missing password"
			utills.Response(w, error, http.StatusBadRequest)
			return
		}

		password := user.Password

		row := db.QueryRow("select * from users where email = $1", user.Email)
		err := row.Scan(&user.ID, &user.Email, &user.Password)

		if err != nil {
			if err == sql.ErrNoRows {
				error.Message = "User Does not exixt"
				utills.Response(w, error, http.StatusBadRequest)
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
			utills.Response(w, error, http.StatusBadRequest)
		}

		spew.Print("suplied password", password)

		token, err := utills.GenerateToken(user)

		if err != nil {
			log.Fatal(nil)
		}

		w.WriteHeader(http.StatusOK)
		jwt.Token = token
		utills.ResponseJSON(w, jwt)
		spew.Print(token)

		w.Write([]byte("Successuffuly Called log in"))
	}

}

func (c Controller) TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was a error")
				}
				return []byte(os.Getenv("SECRET")), nil
			})
			if err != nil {
				errorObject.Message = err.Error()
				utills.Response(w, errorObject, http.StatusUnauthorized)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = err.Error()
				utills.Response(w, errorObject, http.StatusUnauthorized)
				return
			}
		} else {
			errorObject.Message = "Invalid token"
			utills.Response(w, errorObject, http.StatusUnauthorized)
		}
	})

}
