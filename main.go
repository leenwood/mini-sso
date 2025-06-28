package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ЗАХАРДКОЖЕННЫЕ логин и пароль
const (
	hardcodedUsername = "admin"
	hardcodedPassword = "secret"
	jwtSecretKey      = "supersecretkey" // секрет для подписи токенов
	tokenTTL          = time.Hour * 1
)

// структура запроса на логин
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// структура ответа с токеном
type LoginResponse struct {
	Token string `json:"token"`
}

func main() {
	mux := http.NewServeMux()

	// Регистрируем хендлеры
	mux.Handle("/login", loggingMiddleware(http.HandlerFunc(handleLogin)))
	mux.Handle("/auth", loggingMiddleware(http.HandlerFunc(handleAuth)))
	mux.Handle("/api/", loggingMiddleware(authMiddleware(apiHandler)))

	fmt.Println("Server is running on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// Middleware для логирования всех запросов
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Читаем тело запроса (чтобы не потерять его для следующих хендлеров)
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // восстановить тело

		// Логируем запрос
		log.Printf("=== REQUEST ===")
		log.Printf("Time: %s", start.Format(time.RFC3339))
		log.Printf("%s %s", r.Method, r.URL.Path)
		for name, values := range r.Header {
			for _, value := range values {
				log.Printf("Header: %s: %s", name, value)
			}
		}
		if len(bodyBytes) > 0 {
			log.Printf("Body: %s", string(bodyBytes))
		}

		// Оборачиваем ResponseWriter, чтобы поймать статус код
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)

		// Логируем ответ
		log.Printf("=== RESPONSE ===")
		log.Printf("Status: %d", lrw.statusCode)
		log.Println("-----------------------------")
	})
}

// ResponseWriter обёртка, чтобы перехватывать статус-код
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]

	_, err := validateJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Всё ок
	w.WriteHeader(http.StatusOK)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds LoginRequest
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// проверяем логин и пароль
	if creds.Username != hardcodedUsername || creds.Password != hardcodedPassword {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// генерим токен
	tokenString, err := generateJWT(creds.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := LoginResponse{
		Token: tokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// authMiddleware защищает эндпоинты токеном
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// формат: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		claims, err := validateJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// можешь здесь положить claims в контекст, если нужно
		_ = claims

		next(w, r)
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello! You have accessed a protected API endpoint.")
}

// генерим JWT токен
func generateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(tokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecretKey))
}

// валидируем токен
func validateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// проверим, что алгоритм HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(jwtSecretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil

}
