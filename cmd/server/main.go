package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type user struct {
	username string
	pass     string
}

func hashPass(pass string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return string(bytes), err
}

func comparePass(hashedPass, pass string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(pass))
	return err != nil
}

func compareLogin(validate, login user) error {
	if validate.username != login.username {
		return fmt.Errorf("invalid username")
	}
	if comparePass(validate.pass, login.pass) {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func main() {
	pass, err := hashPass("admin")
	if err != nil {
		panic(err)
	}

	validate := user{username: "admin", pass: pass}
	login := user{}

	fmt.Print("Enter to username: ")
	fmt.Scanf("%s", &login.username)

	fmt.Print("Enter to pass: ")
	fmt.Scanf("%s", &login.pass)

	err = compareLogin(validate, login)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Println("Success access!")
}
