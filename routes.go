package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var jwtSecret = []byte("wroenhrpiowe4nf089w4gnervub398r32h0gie rnbio3hj923")

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
		var input UserInput
		var userId, userRole uint
		err := c.ShouldBindJSON(&input)
		if err != nil || !validate(input) {
			log.Println("Получен некорректный json-файл")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Передан некорректный json файл"})
			return
		}
		var login, password string
		if len(input.Email) == 0 {
			login = input.Login
		} else {
			login = input.Email
		}
		password, err = hashPassword(input.Password)
		if err != nil {
			log.Println("Ошибка хеширования пароля")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка хеширования пароля"})
			return
		}
		row := db.Raw(`SELECT auth_sys.login_attempt(?, ?) as (id int8, role_code int4)`, login, password).Row()
		err = row.Scan(&userId, &userRole)
		if err != nil && err != gorm.ErrRecordNotFound {
			log.Println("Ошибка работы с бд")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка работы с бд"})
			return
		}
		if userId == 0 {
			log.Println("Пользователь не найден")
			c.JSON(http.StatusNotFound, gin.H{"result": "Не найден"})
			return
		}
		tokenString := generateToken(userId, userRole)

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	}
}

func generateToken(userId, role uint) string {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["userId"] = userId
	claims["userRole"] = role
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Println("Ошибка генерации токена")
		return ""
	}

	return tokenString
}

func authJWT(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Требуется авторизация"})
		c.Abort()
		return
	}
	tokenString := strings.Split(authHeader, " ")[1]
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
		c.Abort()
		return
	}
}
