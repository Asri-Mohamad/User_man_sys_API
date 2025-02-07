package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
}

var securKey = []byte("This_my_security")
var fileName string = "saveUser.json"

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
func loadFile(fileName string) []user {
	_, err := os.Stat(fileName)
	if err == nil {
		file, err := os.OpenFile(fileName, os.O_RDWR, 0666)
		if err != nil {
			fmt.Println("Error to read file...")
			return nil
		}
		defer file.Close()
		readAll, err := io.ReadAll(file)
		if err != nil {
			fmt.Println("Read date forom file have problem....")
			return nil
		}
		var users []user
		err = json.Unmarshal(readAll, &users)
		if err != nil {
			fmt.Println("Convert to jason file have problem ...")
			return nil
		}
		return users
	}
	file, _ := os.OpenFile(fileName, os.O_CREATE, 0666)
	file.Close()
	return nil
}

func saveFile(fileName string, users []user) {
	file, err := os.OpenFile(fileName, os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Save file have problem....")
		return
	}
	defer file.Close()
	file.Truncate(0)
	file.Seek(0, 0)
	encode := json.NewEncoder(file)
	err = encode.Encode(users)
	if err != nil {
		fmt.Println("Encode to json file have problem...")
		return
	}

}

func main() {
	var users []user

	r := gin.Default()
	users = loadFile(fileName)
	if users == nil {
		users = []user{}
	}
	r.POST("/register", func(c *gin.Context) {
		var newUser user
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error to input data...."})
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Pass), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Hash password have problem ....")

		} else {
			newUser.Pass = string(hashedPassword)
		}

		users = append(users, newUser)
		saveFile(fileName, users)
		c.JSON(http.StatusOK, gin.H{"message": "Register ok...",
			"details": newUser.Name + newUser.Pass}) // اصلاح نام فیلد

	})

	r.POST("/login", func(c *gin.Context) {
		var LoginUser user
		if err := c.ShouldBindJSON(&LoginUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Error to login data...."})
			return
		}
		for _, user := range users {
			if user.Name == LoginUser.Name {
				err := bcrypt.CompareHashAndPassword([]byte(user.Pass), []byte(LoginUser.Pass))
				if err == nil {

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
		}
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid user name or password"})
	})
	r.GET("/profile", func(c *gin.Context) {
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
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token not valid or convert problem...."})

			return
		}

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
			"exp_readable": clime["exp_readable"].(string),
			"exp":          clime["exp"].(float64),
		})

	})

	r.Run(":8080")
}
