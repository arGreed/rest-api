package main

import (
	"encoding/json"
	"errors"
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
		err := c.ShouldBindJSON(&input)
		if err != nil || !validate(input) {
			log.Println("Получен некорректный json-файл")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Передан некорректный json файл"})
			return
		}

		// Определяем, что используется: логин или email
		var login string
		if len(input.Email) == 0 {
			login = input.Login
		} else {
			login = input.Email
		}

		// Запрос к базе данных для получения хеша пароля и данных пользователя
		var storedPasswordHash string
		var userId, userRole uint
		var role int
		row := db.Raw(`SELECT password, id, role_code FROM auth_sys.user WHERE login = ? OR email = ?`, login, login).Row()
		err = row.Scan(&storedPasswordHash, &userId, &role)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				log.Println("Пользователь не найден")
				c.JSON(http.StatusNotFound, gin.H{"result": "Не найден"})
				return
			}
			log.Println("Ошибка работы с БД:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка работы с БД"})
			return
		}

		// Проверяем соответствие пароля
		err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(input.Password))
		if err != nil {
			log.Println("Неверный пароль")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный пароль"})
			return
		}

		// Генерация токена
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
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("неожиданный метод подписи")
		}
		return jwtSecret, nil
	})
	if err != nil {
		log.Println("Ошибка парсинга jwt")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка парсинга jwt"})
	}
	if !token.Valid {
		log.Println("Ошибка проверки токена:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
		c.Abort()
		return
	}
	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки токена"})
		c.Abort()
		return
	}
	userId, err := (*claims)["userId"].(json.Number).Int64()
	if err != nil || userId == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
		c.Abort()
		return
	}
	userRole, err := (*claims)["userRole"].(json.Number).Int64()
	if err != nil || userRole == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
		c.Abort()
		return
	}

	c.Set("userId", uint(userId))
	c.Set("userRole", uint(userRole))

	c.Next()
}
