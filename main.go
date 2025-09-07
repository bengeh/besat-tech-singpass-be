package main

import (
	"log"

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

	r := gin.Default()
	store := cookie.NewStore([]byte("super-secret-long-random-key-here"))
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

	log.Printf("listening :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
