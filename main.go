package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type user struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
}

var securKey = []byte("This_my_security")

func makeToken(newUser user) (string, error) {

	claims := jwt.MapClaims{
		"username": newUser.Name,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(securKey)

}

func validationToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("algoritm token not valid")
		}

		return securKey, nil
	})

	if err != nil {
		fmt.Println("error 2")
		return nil, err
	}

	return token, nil

}

func main() {
	var users []user

	r := gin.Default()

	r.POST("/r", func(c *gin.Context) {
		var newUser user
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error to input data...."})
			return
		}
		users = append(users, newUser)
		c.JSON(http.StatusOK, gin.H{"message": "Register ok...",
			"messsage": newUser.Name + newUser.Pass})
	})

	r.POST("/l", func(c *gin.Context) {
		var LoginUser user
		if err := c.ShouldBindJSON(&LoginUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Error to login data...."})
			return
		}
		for _, user := range users {
			if user.Name == LoginUser.Name && user.Pass == LoginUser.Pass {
				if token, err := makeToken(user); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Canat make the token..."})
					return
				} else {
					c.JSON(http.StatusOK, gin.H{
						"message": "Wellcom to system .... this is your token",
						"token":   token})

					return
				}

			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid user name or password"})
	})
	r.GET("/p", func(c *gin.Context) {
		headAtu := c.GetHeader("Authorization")
		if headAtu == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid heder....."})

			return
		}
		tokenString := strings.TrimPrefix(headAtu, "Bearer ")

		if tokenString == headAtu {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "can not finde token...."})

			return
		}
		token, err := validationToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token not valid or convert problem...."})

			return
		}
		if token.Valid {
			c.JSON(http.StatusOK, gin.H{"Message": "This is a valid token......",
				"token":   tokenString,
				"message": "Wellcom to system ...."})

			clime, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "claim map have problem..."})
				return
			}
			expTime := time.Unix(int64(clime["exp"].(float64)), 0)
			clime["exp_readable"] = expTime.Format("2006-01-02 15:04:05")

			c.JSON(http.StatusOK, gin.H{"username": clime["username"].(string),
				"exp_readebel": clime["exp_readable"].(string),
				"exp":          clime["exp"].(float64),
			})
		}
	})

	r.Run(":8080")
}
