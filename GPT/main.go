package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var users = []User{} // برای ذخیره‌سازی موقتی کاربران

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// متد برای تولید توکن JWT
func generateToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("secret")) // "secret" کلید امضای توکن است
}

// متد برای اعتبارسنجی توکن JWT
func validateToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte("secret"), nil
	})
}

func main() {
	r := gin.Default()

	// مسیر ثبت‌نام (Register)
	r.POST("/register", func(c *gin.Context) {
		var newUser User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		users = append(users, newUser)
		c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
	})

	// مسیر ورود (Login)
	r.POST("/login", func(c *gin.Context) {
		var loginUser User
		if err := c.ShouldBindJSON(&loginUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		for _, user := range users {
			if user.Username == loginUser.Username && user.Password == loginUser.Password {
				token, err := generateToken(user.Username)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": token})
				return
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	})

	// مسیر پروفایل (Profile) - نیاز به توکن دارد
	r.GET("/profile", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		// جدا کردن Bearer از توکن
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader { // یعنی Bearer وجود ندارد
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			return
		}

		token, err := validateToken(tokenString)
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		username := claims["username"].(string)
		c.JSON(http.StatusOK, gin.H{"message": "Welcome to your profile!", "username": username})
	})

	r.Run(":8080")
}
