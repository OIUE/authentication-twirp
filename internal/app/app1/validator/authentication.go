package validator

import (
	"github.com/pepeunlimited/authentication-twirp/authrpc"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/twitchtv/twirp"
)

type AuthenticationServerValidator struct {}

func NewAuthenticationServerValidator() AuthenticationServerValidator {
	return AuthenticationServerValidator{}
}

func (AuthenticationServerValidator) SignIn(params *authrpc.SignInParams) error {
	if validator.IsEmpty(params.Password) {
		return twirp.RequiredArgumentError("password")
	}
	if validator.IsEmpty(params.Username) {
		return twirp.RequiredArgumentError("password")
	}
	return nil
}

func (AuthenticationServerValidator) RefreshAccessToken(params *authrpc.RefreshAccessTokenParams) error {
	if validator.IsEmpty(params.RefreshToken) {
		return twirp.RequiredArgumentError("refresh_token")
	}
	return nil
}

func (AuthenticationServerValidator) VerifyAccessToken(params *authrpc.VerifyAccessTokenParams) error {
	if validator.IsEmpty(params.AccessToken) {
		return twirp.RequiredArgumentError("access_token")
	}
	return nil
}
