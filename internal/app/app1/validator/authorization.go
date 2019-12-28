package validator

import (
	"github.com/pepeunlimited/authorization-twirp/rpc"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/twitchtv/twirp"
)

type AuthorizationServerValidator struct {}


func NewAuthorizationServerValidator() AuthorizationServerValidator {
	return AuthorizationServerValidator{}
}

func (AuthorizationServerValidator) SignIn(params *rpc.SignInParams) error {
	if validator.IsEmpty(params.Password) {
		return twirp.RequiredArgumentError("password")
	}
	if validator.IsEmpty(params.Username) {
		return twirp.RequiredArgumentError("password")
	}
	return nil
}

func (AuthorizationServerValidator) Refresh(params *rpc.RefreshParams) error {
	if validator.IsEmpty(params.RefreshToken) {
		return twirp.RequiredArgumentError("refresh_token")
	}
	return nil
}

func (AuthorizationServerValidator) Verify(params *rpc.VerifyParams) error {
	if validator.IsEmpty(params.Token) {
		return twirp.RequiredArgumentError("token")
	}
	return nil
}
