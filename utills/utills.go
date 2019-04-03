package utills

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"../models"
	"github.com/dgrijalva/jwt-go"
)

func ResponseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)

}

func Response(w http.ResponseWriter, err models.Error, status int) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(err)
}

func GenerateToken(user models.User) (string, error) {
	secret := os.Getenv("SECRET")
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
