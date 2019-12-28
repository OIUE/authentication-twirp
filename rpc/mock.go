package rpc

import (
	"context"
	"github.com/pepeunlimited/microservice-kit/errorz"
)

type Mock struct {
	Errors 		errorz.Stack
}

func (m *Mock) SignIn(ctx context.Context, params *SignInParams) (*SignInResponse, error) {
	return nil, nil
}

func (m *Mock) Refresh(ctx context.Context, parmas *RefreshParams) (*RefreshResponse, error) {
	return nil, nil
}

func (m *Mock) Verify(ctx context.Context, params *VerifyParams) (*VerifyResponse, error) {
	if m.Errors.IsEmpty() {
		return &VerifyResponse{
			Username:             "kakkaliisa",
			Email:                "kakkaliisa@gmail.com",
			UserId:               1,
			Roles:                []string{"User"},
		},
		nil
	}
	return nil, m.Errors.Pop()
}

func NewAuthorizationMock(errors []error) AuthorizationService {
	return &Mock{Errors:errorz.NewErrorStack(errors)}
}