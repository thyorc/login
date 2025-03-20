package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type users struct {
	Username string `json:"username"`
	Pass     string `json:"password"`
}

func hashPass(pass string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return string(bytes), err
}

func comparePass(hashedPass, pass string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(pass))
	return err != nil
}

func compareLogin(user, login users) error {
	if user.Username != login.Username {
		return fmt.Errorf("invalid username")
	}
	if comparePass(user.Pass, login.Pass) {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func main() {
	pass, err := hashPass("admin")
	if err != nil {
		panic(err)
	}

	user := users{Username: "admin", Pass: pass}

	r := gin.Default()

	r.POST("/login", func(ctx *gin.Context) {
		var login users
		if err := ctx.ShouldBindJSON(&login); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data"})
			return
		}

		err = compareLogin(user, login)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"Hello": "World"})
	})

	r.Run(":8080")
}
