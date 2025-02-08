package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	pingRoute string = "/ping"
)

/*
? Функция для проверки состояния соединения.
*/
func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "connected"})
}
