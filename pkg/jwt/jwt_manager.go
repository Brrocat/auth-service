package jwt

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"os"
	"time"
)

type Manager struct {
	privateKey        *rsa.PrivateKey
	publicKey         *rsa.PublicKey
	expiration        time.Duration
	refreshExpiration time.Duration
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func NewManager(privateKeyPath, publicKeyPath string, expiration time.Duration) *Manager {
	privateKey := loadPrivateKey(privateKeyPath)
	publicKey := loadPublicKey(publicKeyPath)

	// Refresh tokens typically have longer expiration
	refreshExpiration := expiration * 24 * 7 // 7 days

	return &Manager{
		privateKey:        privateKey,
		publicKey:         publicKey,
		expiration:        expiration,
		refreshExpiration: refreshExpiration,
	}
}

func loadPrivateKey(path string) *rsa.PrivateKey {
	keyFile, err := os.Open(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to load private key: %v", err))
	}
	defer keyFile.Close()

	keyData, err := io.ReadAll(keyFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to read private key: %v", err))
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse private key: %v", err))
	}

	return privateKey
}

func loadPublicKey(path string) *rsa.PublicKey {
	keyFile, err := os.Open(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to load public key: %v", err))
	}
	defer keyFile.Close()

	keyData, err := io.ReadAll(keyFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to read public key: %v", err))
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse public key: %v", err))
	}

	return publicKey
}

func (m *Manager) GenerateAccessToken(userID, email, role string) (string, error) {
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
}

func (m *Manager) GenerateRefreshToken(userID string) (string, error) {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.refreshExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
}

func (m *Manager) VerifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (m *Manager) ExtractClaims(tokenString string) (*Claims, error) {
	claims := &Claims{}

	//Parse without verification to extract claims
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok {
		return claims, nil
	}
	return nil, fmt.Errorf("failed to extract claims")
}

func (m *Manager) GetExpiration() time.Duration {
	return m.expiration
}

func (m *Manager) GetRefreshExpiration() time.Duration {
	return m.refreshExpiration
}
