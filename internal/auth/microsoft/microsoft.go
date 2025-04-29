// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package microsoft

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/googleapis/genai-toolbox/internal/auth"
)

const AuthServiceKind string = "microsoft"

var _ auth.AuthServiceConfig = Config{}

type Config struct {
	Name     string `yaml:"name" validate:"required"`
	Kind     string `yaml:"kind" validate:"required"`
	ClientID string `yaml:"clientId" validate:"required"`
	TenantID string `yaml:"tenantId,omitempty"` // Optional: restrict auth to a specific Azure AD tenant
}

func (cfg Config) AuthServiceConfigKind() string {
	return AuthServiceKind
}

func (cfg Config) Initialize() (auth.AuthService, error) {
	a := &AuthService{
		Name:     cfg.Name,
		Kind:     AuthServiceKind,
		ClientID: cfg.ClientID,
		TenantID: cfg.TenantID,
	}
	return a, nil
}

var _ auth.AuthService = AuthService{}

type AuthService struct {
	Name     string `yaml:"name"`
	Kind     string `yaml:"kind"`
	ClientID string `yaml:"clientId"`
	TenantID string `yaml:"tenantId,omitempty"` // Optional: restrict auth to a specific Azure AD tenant
}

func (a AuthService) AuthServiceKind() string {
	return AuthServiceKind
}

func (a AuthService) GetName() string {
	return a.Name
}

func (a AuthService) GetClaimsFromHeader(ctx context.Context, h http.Header) (map[string]any, error) {
	tokenString := h.Get(a.Name + "_token")
	if tokenString == "" {
		return nil, nil
	}

	issuer := "https://login.microsoftonline.com/common/v2.0"
	jwksURL := "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	if a.TenantID != "" {
		issuer = "https://login.microsoftonline.com/" + a.TenantID + "/v2.0"
		jwksURL = "https://login.microsoftonline.com/" + a.TenantID + "/discovery/v2.0/keys"
	}
	provider := oidc.NewRemoteKeySet(ctx, jwksURL)
	verifier := oidc.NewVerifier(issuer, provider, &oidc.Config{ClientID: a.ClientID})

	idToken, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %w", err)
	}
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}
	return claims, nil
}
