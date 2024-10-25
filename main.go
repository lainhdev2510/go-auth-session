package main

import (
	"log"
	"os"
	"time"

	"go-auth-session/config"
	"go-auth-session/handlers"
	"go-auth-session/middleware"
	"go-auth-session/models"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/redis/v3"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect to database
	config.ConnectDB()

	// Migrate the schema
	config.DB.AutoMigrate(&models.User{})

	// Initialize Redis storage
	redisStorage := redis.New(redis.Config{
		URL: os.Getenv("REDIS_URL"),
	})

	// Initialize session store
	store := session.New(session.Config{
		Storage:        redisStorage,
		Expiration:     24 * time.Hour,
		CookieHTTPOnly: true,
		CookieSecure:   true,
	})

	// Initialize HTML template engine
	engine := html.New("./templates", ".html")

	// Create a new Fiber app
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(store)

	// Set up routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"Title": "Home",
		})
	})

	app.Get("/login", authHandler.Login)
	app.Post("/login", authHandler.LoginPost)
	app.Get("/signup", authHandler.Signup)
	app.Post("/signup", authHandler.SignupPost)
	app.Get("/logout", authHandler.Logout)

	// Protected route
	app.Get("/authenticated", middleware.AuthMiddleware(store), authHandler.Authenticated)

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}
