package controllers

import (
	"fmt"
	"net/http"

	"../utills"
)

type Controller struct{}

func (c Controller) ProtectedEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("protectedEndpoint Invoked")
		utills.ResponseJSON(w, "Yes")
	}

}
