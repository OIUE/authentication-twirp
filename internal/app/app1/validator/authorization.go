package validator

import (
	"github.com/pepeunlimited/authorization-twirp/rpcauthorization"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/twitchtv/twirp"
)

type AuthorizationServerValidator struct {}


func NewAuthorizationServerValidator() AuthorizationServerValidator {
	return AuthorizationServerValidator{}
}

func (AuthorizationServerValidator) SignIn(params *rpcauthorization.SignInParams) error {
	if validator.IsEmpty(params.Password) {
		return twirp.RequiredArgumentError("password")
	}
	if validator.IsEmpty(params.Username) {
		return twirp.RequiredArgumentError("password")
	}
	return nil
}

func (AuthorizationServerValidator) RefreshAccessToken(params *rpcauthorization.RefreshAccessTokenParams) error {
	if validator.IsEmpty(params.RefreshToken) {
		return twirp.RequiredArgumentError("refresh_token")
	}
	return nil
}

func (AuthorizationServerValidator) VerifyAccessToken(params *rpcauthorization.VerifyAccessTokenParams) error {
	if validator.IsEmpty(params.AccessToken) {
		return twirp.RequiredArgumentError("access_token")
	}
	return nil
}
