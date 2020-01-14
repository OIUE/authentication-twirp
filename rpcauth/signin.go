package rpcauth

import (
	"context"
	"github.com/pepeunlimited/microservice-kit/rpcz"
	"github.com/twitchtv/twirp"
)

func IsSignedIn(ctx context.Context, authentication AuthenticationService) (*VerifyAccessTokenResponse, error) {
	token, err := rpcz.GetAuthorizationWithoutPrefix(ctx)
	if err != nil {
		return nil, twirp.RequiredArgumentError("authorization")
	}
	// verify the token from the authorization service: blacklist and expired..
	resp, err := authentication.VerifyAccessToken(ctx, &VerifyAccessTokenParams{AccessToken:token})
	if err != nil {
		return nil, err
	}
	return resp, nil
}