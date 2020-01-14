package rpcauth

import (
	"context"
	"github.com/pepeunlimited/microservice-kit/errorz"
)

type AuthenticationMock struct {
	Errors 		errorz.Stack
	Username    string
	Email       string
	UserId      int64
	Roles       []string
}

func (m *AuthenticationMock) SignIn(ctx context.Context, params *SignInParams) (*SignInResponse, error) {
	return nil, nil
}

func (m *AuthenticationMock) RefreshAccessToken(ctx context.Context, parmas *RefreshAccessTokenParams) (*RefreshAccessTokenResponse, error) {
	return nil, nil
}

func (m *AuthenticationMock) VerifyAccessToken(ctx context.Context, params *VerifyAccessTokenParams) (*VerifyAccessTokenResponse, error) {
	if m.Errors.IsEmpty() {
		return &VerifyAccessTokenResponse{
			Username:             m.Username,
			Email:                m.Email,
			UserId:               m.UserId,
			Roles:                m.Roles,
		},
		nil
	}
	return nil, m.Errors.Pop()
}

func NewAuthenticationMock(errors []error) AuthenticationService {
	return &AuthenticationMock{
		Errors:   errorz.NewErrorStack(errors),
		Username: "kakkaliisa",
		Email:    "kakkaliisa@gmail.com",
		UserId:   1,
		Roles:    []string{"User"},
	}
}