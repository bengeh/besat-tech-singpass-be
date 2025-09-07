package main

import (
	"log"
	"net/http"

	"beast-tech-singpass-be/config"
	"beast-tech-singpass-be/handlers"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadFromFile("config/config.json")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	handler, err := handlers.NewSingpassHandler(cfg)
	if err != nil {
		log.Fatalf("init singpass handler: %v", err)
	}

	r := gin.Default()
	store := cookie.NewStore([]byte("super-secret-long-random-key-here"))

	// Configure session cookie for production (Render uses HTTPS)
	store.Options(sessions.Options{
		Path:     "/",
		Domain:   "",                   // 👈 must match your backend domain
		MaxAge:   3600,                 // 1 hour
		HttpOnly: true,                 // JS can’t access cookie
		Secure:   false,                // required for HTTPS
		SameSite: http.SameSiteLaxMode, // allow cross-site OAuth redirects
	})

	// Attach session middleware
	r.Use(sessions.Sessions("singpass-session", store))

	// routes
	r.GET("/.well-known/jwks.json", handler.JWKS)
	r.GET("/login", handler.Login)
	r.GET("/callback", handler.Callback)

	log.Printf("listening :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
