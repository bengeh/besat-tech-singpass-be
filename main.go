package main

import (
	"beast-tech-singpass-be/config"
	"beast-tech-singpass-be/handlers"
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadFromFile("config/config.json")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	r := gin.Default()
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Println("WARNING: SESSION_SECRET not set, using dev fallback (do NOT use in prod)")
		sessionSecret = "dev-fallback-please-change"
	}
	store := cookie.NewStore([]byte(sessionSecret))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true, // required if SameSite=None
		SameSite: http.SameSiteNoneMode,
	})
	// Attach session middleware
	r.Use(sessions.Sessions("singpass-session", store))

	handler, err := handlers.NewSingpassHandler(cfg)
	if err != nil {
		log.Fatalf("init singpass handler: %v", err)
	}

	// routes
	r.GET("/.well-known/jwks.json", handler.JWKS)
	r.GET("/login", handler.Login)
	r.GET("/callback", handler.Callback)
	r.GET("/userinfo", handler.Userinfo)
	r.GET("/userinfojwe", handler.UserinfoJWEHandler)
	r.POST("/decrypt", handler.DecryptJWEHandler)

	log.Printf("listening :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
