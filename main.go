package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var dsn string = "host=localhost user=postgres password=admin dbname=postgres port=5432 sslmode=disable TimeZone=UTC"

func storageInit() (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func main() {
	db, err := storageInit()
	if err != nil {
		log.Println("Ошибка подключения к базе данных!")
		return
	}
	//? Базовый маршрутизатор приложения.
	router := gin.Default()

	//? PING - проверка;
	router.GET(pingRoute, ping)
	//? Регистрация пользователя;
	router.POST(registerRoute, register(db))
	//? Логин в систему
	router.GET(loginRoute, login(db))

	router.Run(":8081")
}
