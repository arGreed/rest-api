package main

import "time"

/*
? Хранилище данных, полученных из базы при успешной авторизации пользователя.
*/
type User struct {
	Id        uint      `json:"" gorm:"id"`
	Login     string    `json:"login" gorm:"login"`
	Email     string    `json:"email" gorm:"email"`
	Password  string    `json:"-" gorm:"password"`
	CreatedAt time.Time `json:"created_at" gorm:"created_at"`
	UpdatedAt time.Time `json:"last_login" gorm:"last_login"`
}

/*
? Структура данных, получаемая от пользователя.
*/
type UserInput struct {
	Login    string `json:"login" gorm:"login"`
	Email    string `json:"email" gorm:"email"`
	Password string `json:"password" gorm:"password"`
}
