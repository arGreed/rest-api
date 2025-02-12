package main

import (
	"strings"
	"time"
)

/*
? Хранилище данных, полученных из базы при успешной авторизации пользователя.
*/
type User struct {
	Id        uint      `json:"" gorm:"column:id"`
	Login     string    `json:"login" gorm:"column:login"`
	Email     string    `json:"email" gorm:"column:email"`
	Password  string    `json:"-" gorm:"column:password"`
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at"`
	UpdatedAt time.Time `json:"last_login" gorm:"column:last_login"`
}

func (user User) isValid() bool {
	return !(len(user.Login) < 5 || !strings.Contains(user.Email, "@") || len(user.Password) < 5)
}

/*
? Структура данных, получаемая от пользователя.
*/
type UserInput struct {
	Login    string `json:"login" gorm:"column:login"`
	Email    string `json:"email" gorm:"column:email"`
	Password string `json:"password" gorm:"column:password"`
}

func (inp UserInput) isValid() bool {
	//return (len(inp.Password) < 5 || (len(inp.Login) < 5 && len(inp.Email) < 5) || (!strings.Contains(inp.Email, "@") && len(inp.Email) > 5))
	return true
}

type validator interface {
	isValid() bool
}

func validate(v validator) bool {
	return v.isValid()
}
