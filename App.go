package main

import (
	"database/sql"
	"github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
	"time"
)

var PATH = "/var/www/passwd/"

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type regInfo struct {
	Username     string `form:"username" json:"username" binding:"required"`
	Password     string `form:"password" json:"password" binding:"required"`
	EncryptedKey string `form:"encryptedKey" json:"encryptedKey" binding:"required"`
}

type syncNum struct {
	SyncNumber int `form:"syncNumber" json:"syncNumber" binging:"required"`
}

var identityKey = "id"
var db *sql.DB

func getDatabase(c *gin.Context) {
	user, _ := c.Get(identityKey)
	c.File(PATH + "userPasswords/" + user.(*User).UserName)
}

func pushDatabase(c *gin.Context) {
	user, _ := c.Get(identityKey)
	file, err1 := c.FormFile("file")
	if err1 != nil {
		c.JSON(http.StatusConflict, gin.H{
			"code": err1,
		})
		return
	}
	err := c.SaveUploadedFile(file, PATH+"userPasswords/"+user.(*User).UserName)
	if err != nil {
		log.Fatal(err)
	}
	//row := db.QueryRow("SELECT syncNumber FROM Users WHERE username = $1", user.(*User).UserName)
	//var syncNumber int
	//row.Scan(&syncNumber)
	c.JSON(http.StatusOK, gin.H{
		"status": "uploaded",
	})
}

func setSyncNumber(c *gin.Context) {
	user, _ := c.Get(identityKey)
	var tmp syncNum
	err := c.ShouldBind(&tmp)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": http.StatusBadRequest,
		})
		return
	}
	_, err2 := db.Exec("UPDATE Users SET syncNumber = $1 WHERE username = $2", tmp.SyncNumber, user.(*User).UserName)
	if err2 != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": http.StatusBadRequest,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "OK",
	})
}

func getSyncNumber(c *gin.Context) {
	user, _ := c.Get(identityKey)
	row := db.QueryRow("SELECT syncNumber FROM Users WHERE username = $1", user.(*User).UserName)
	var syncNumber int
	row.Scan(&syncNumber)
	c.JSON(http.StatusOK, gin.H{
		"syncNumber": syncNumber,
	})
}

// User
type User struct {
	UserName               string
	EncryptedEncryptionKey string
}

func main() {
	db, _ = sql.Open("sqlite3", PATH+"users")
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8080"
	}

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		LoginResponse: func(c *gin.Context, code int, token string, expire time.Time, claims map[string]interface{}) {
			c.JSON(http.StatusOK, gin.H{
				"token":        token,
				"expire":       expire.Format(time.RFC3339),
				"encryptedKey": claims["encryptedKey"],
			})
		},

		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey:    v.UserName,
					"encryptedKey": v.EncryptedEncryptionKey,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &User{
				UserName:               claims[identityKey].(string),
				EncryptedEncryptionKey: claims["encryptedKey"].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			action := c.DefaultQuery("action", "login")
			if action == "login" {
				var loginVals, tmp login
				if err := c.ShouldBind(&loginVals); err != nil {
					return "", jwt.ErrMissingLoginValues
				}
				userID := loginVals.Username
				password := loginVals.Password
				var key string

				row := db.QueryRow("select username, password, encryptedKey from Users where username = $1", userID)
				row.Scan(&tmp.Username, &tmp.Password, &key)

				if userID == tmp.Username && password == tmp.Password {
					return &User{
						UserName:               userID,
						EncryptedEncryptionKey: key,
					}, nil
				}
				return nil, jwt.ErrFailedAuthentication
			} else if action == "reg" {
				var login string
				var json regInfo
				if err := c.ShouldBindJSON(&json); err != nil {
					//c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return nil, jwt.ErrFailedAuthentication
				}
				row := db.QueryRow("select username from Users where username = $1", json.Username)
				row.Scan(&login)
				if login == json.Username {
					return nil, jwt.ErrFailedAuthentication
				}
				_, err := db.Exec("insert into Users (username, password, syncNumber, encryptedKey) values  ($1, $2, $3, $4)", json.Username, json.Password, 0, json.EncryptedKey)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					panic(err)
				}
				return &User{
					UserName:               json.Username,
					EncryptedEncryptionKey: json.EncryptedKey,
				}, nil
			}
			return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			return true
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},

		TokenLookup: "header: Authorization, query: token, cookie: jwt",

		// TokenHeadName is a string in the header. Default value is "Bearer"
		TokenHeadName: "Bearer",

		// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
		TimeFunc: time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/getDatabase", getDatabase)
		auth.POST("/pushDatabase", pushDatabase)
		auth.GET("/getSyncNumber", getSyncNumber)
		auth.POST("/setSyncNumber", setSyncNumber)
	}

	if err := http.ListenAndServe("127.0.0.1:"+port, r); err != nil {
		log.Fatal(err)
	}
}
