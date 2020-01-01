package rpc

import (
	"context"
	"github.com/pepeunlimited/microservice-kit/errorz"
)

type Mock struct {
	Errors 		errorz.Stack
	Username    string
	Email       string
	UserId      int64
	Roles       []string
}

func (m *Mock) SignIn(ctx context.Context, params *SignInParams) (*SignInResponse, error) {
	return nil, nil
}

func (m *Mock) RefreshAccessToken(ctx context.Context, parmas *RefreshAccessTokenParams) (*RefreshAccessTokenResponse, error) {
	return nil, nil
}

func (m *Mock) VerifyAccessToken(ctx context.Context, params *VerifyAccessTokenParams) (*VerifyAccessTokenResponse, error) {
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

func NewAuthorizationMock(errors []error) AuthorizationService {
	return &Mock{
		Errors:   errorz.NewErrorStack(errors),
		Username: "kakkaliisa",
		Email:    "kakkaliisa@gmail.com",
		UserId:   1,
		Roles:    []string{"User"},
	}
}