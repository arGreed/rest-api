package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	userTab string = "auth_sys.user"
)

var (
	pingRoute     string = "/ping"
	registerRoute string = "/register"
	loginRoute    string = "/login"
)

/*
? Функция для проверки состояния соединения.
*/
func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "connected"})
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func register(db *gorm.DB) func(c *gin.Context) {
	return func(c *gin.Context) {
		var input UserInput
		err := c.ShouldBindJSON(&input)
		if err != nil {
			log.Println("Ошибка, проблема с json файлом при регистрации!")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Проверьте введённые данные и повторите попытку!"})
			return
		}
		if !validate(input) {
			log.Println("Структура полученного json некорректна")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Получены некорректные данные"})
			return
		}
		var user User

		result := db.Table(userTab).Where("login = ? or email = ?", input.Login, input.Email).First(&user)

		if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
			log.Println("Ошибка работы с базой данных")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка работы с базой данных"})
			return
		}
		if user.Id != 0 {
			log.Println("Попытка регистрации пользователя по совпадающей почте или логину")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Попытка регистрации пользователя по уже сохранённым значениям"})
			return
		}

		hash, err := hashPassword(input.Password)

		if err != nil {
			log.Println("Ошибка хеширования пароля")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка хеширования пароля"})
			return
		}
		newUser := User{
			Login:    input.Login,
			Email:    input.Email,
			Password: hash,
		}
		result = db.Table(userTab).Create(&newUser)
		if result.Error != nil {
			log.Println(result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании нового пользователя"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"result": "Пользователь успешно создан"})
	}
}

func login(db *gorm.DB) func(c *gin.Context) {
	return func(c *gin.Context) {

	}
}
