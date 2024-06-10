package cognitoJwtAuthenticator

import (
	"context"
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

// We want to get details from the access token: client_id and unique user identifier.
// Let's add client_id. We can verify, if it match our App cliet ID in AWS Cognito User Pool
// We can also add user identifier (f.e. "username") to use it with our App

type AWSCognitoClaims struct {
	Client_ID string `json:"client_id"`
	Username  string `json:"username"`
	jwt.StandardClaims
}

// FetchPublicKeys fetches the public keys from AWS Cognito
func FetchPublicKeys(ctx context.Context, region, userPoolId string) (jwk.Set, error) {
	publicKeysURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId)
	publicKeySet, err := jwk.Fetch(ctx, publicKeysURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public keys: %w", err)
	}
	return publicKeySet, nil
}

// ValidateToken validates the given token string
func ValidateToken(ctx context.Context, region, userPoolId, tokenString string) (*AWSCognitoClaims, error) {
	publicKeySet, err := FetchPublicKeys(ctx, region, userPoolId)
	if err != nil {
		return nil, err
	}

	// JWT Parse - it's actually doing parsing, validation and returns back a token.
	// Use .Parse or .ParseWithClaims methods from https://github.com/dgrijalva/jwt-go
	token, err := jwt.ParseWithClaims(tokenString, &AWSCognitoClaims{}, func(token *jwt.Token) (interface{}, error) {

		// Verify if the token was signed with correct signing method
		// AWS Cognito is using RSA256 in my case
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get "kid" value from token header
		// "kid" is shorthand for Key ID
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid header not found")
		}

		// "kid" must be present in the public keys set
		key, found := publicKeySet.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key %v not found", kid)
		}

		var tokenKey interface{}
		if err := key.Raw(&tokenKey); err != nil {
			return nil, errors.New("failed to create token key")
		}

		return tokenKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token problem: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("token is invalid")
	}

	// Check client_id attribute from the access token
	claims, ok := token.Claims.(*AWSCognitoClaims)
	if !ok {
		return nil, errors.New("there is a problem to get claims")
	}

	return claims, nil
}
