package handlers

import (
	"go-auth-session/config"
	"go-auth-session/models"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	store *session.Store
}

func NewAuthHandler(store *session.Store) *AuthHandler {
	return &AuthHandler{store: store}
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login",
	})
}

func (h *AuthHandler) LoginPost(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	var user models.User
	result := config.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create session"})
	}

	sess.Set("user_id", user.ID)
	if err := sess.Save(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save session"})
	}

	return c.Redirect("/authenticated")
}

func (h *AuthHandler) Signup(c *fiber.Ctx) error {
	return c.Render("signup", fiber.Map{
		"Title": "Sign Up",
	})
}

func (h *AuthHandler) SignupPost(c *fiber.Ctx) error {
	username := c.FormValue("username")
	email := c.FormValue("email")
	password := c.FormValue("password")

	user := models.User{
		Username: username,
		Email:    email,
		Password: password,
	}

	result := config.DB.Create(&user)
	if result.Error != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Failed to create user"})
	}

	return c.Redirect("/login")
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get session"})
	}

	if err := sess.Destroy(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to destroy session"})
	}

	return c.Redirect("/")
}

func (h *AuthHandler) Authenticated(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Redirect("/login")
	}

	userId := sess.Get("user_id")
	if userId == nil {
		return c.Redirect("/login")
	}

	var user models.User
	result := config.DB.First(&user, userId)
	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch user"})
	}

	return c.Render("authenticated", fiber.Map{
		"Title":    "Authenticated",
		"Username": user.Username,
	})
}
