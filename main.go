package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

var users []User

type ErrorResponse struct {
	Message string `json:"message"`
}

// TokenResponse representa la estructura de respuesta del token JWT
type TokenResponse struct {
	Token string `json:"token"`
}

// Función principal
func main() {
	router := mux.NewRouter()

	router.HandleFunc("/register", registerUser).Methods("POST")
	router.HandleFunc("/login", loginUser).Methods("POST")

	http.ListenAndServe(":8080", router)
}

// Función para validar el correo electrónico
func isValidEmail(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	return regexp.MustCompile(emailRegex).MatchString(email)
}

func isValidPassword(password string) bool {
	if len(password) < 6 || len(password) > 12 {
		return false
	}

	hasUpperCase := false
	hasLowerCase := false
	hasSpecialChar := false
	hasNumber := false

	specialChars := "@$&"

	for _, char := range password {
		if strings.ContainsRune(specialChars, char) {
			hasSpecialChar = true
		}
		if 'A' <= char && char <= 'Z' {
			hasUpperCase = true
		}
		if 'a' <= char && char <= 'z' {
			hasLowerCase = true
		}
		if '0' <= char && char <= '9' {
			hasNumber = true
		}
	}

	return hasUpperCase && hasLowerCase && hasSpecialChar && hasNumber
}

// Función para validar el teléfono
func isValidPhone(phone string) bool {
	phoneRegex := `^\d{10}$`
	return regexp.MustCompile(phoneRegex).MatchString(phone)
}

// Función para registrar un nuevo usuario
func registerUser(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Error al decodificar la solicitud"})
		return
	}

	if newUser.Username == "" || newUser.Email == "" || newUser.Phone == "" || newUser.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Faltan campos en la solicitud"})
		return
	}

	// Validar el correo electrónico
	if !isValidEmail(newUser.Email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "El correo electrónico no es válido"})
		return
	}

	// Validar el teléfono
	if !isValidPhone(newUser.Phone) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "El teléfono no es válido"})
		return
	}

	// Validar la contraseña
	if !isValidPassword(newUser.Password) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "La contraseña no cumple con los requisitos mínimos"})
		return
	}

	// Verificar si el correo electrónico ya está registrado
	for _, existingUser := range users {
		if existingUser.Email == newUser.Email {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "El correo electrónico ya se encuentra registrado"})
			return
		}
	}

	// Verificar si el teléfono ya está registrado
	for _, existingUser := range users {
		if existingUser.Phone == newUser.Phone {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "El teléfono ya se encuentra registrado"})
			return
		}
	}
	users = append(users, newUser)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newUser)
}

// Función para iniciar sesión
func loginUser(w http.ResponseWriter, r *http.Request) {
	var loginInfo struct {
		UsernameOrEmail string `json:"username_or_email"`
		Password        string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&loginInfo)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Error al decodificar la solicitud"})
		return
	}
	if loginInfo.UsernameOrEmail == "" || loginInfo.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Faltan campos en la solicitud"})
		return
	}

	// Verificar las credenciales del usuario
	var foundUser *User
	for _, user := range users {
		if (user.Username == loginInfo.UsernameOrEmail || user.Email == loginInfo.UsernameOrEmail) && user.Password == loginInfo.Password {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Usuario / contraseña incorrectos"})
		return
	}

	// Generar token JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": foundUser.Username,
		"email":    foundUser.Email,
		"phone":    foundUser.Phone,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token válido por 24 horas
	})
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Error al generar el token"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TokenResponse{Token: tokenString})
}
