package server

import (
	"context"
	"github.com/pepeunlimited/authorization-twirp/internal/app/app1/validator"
	"github.com/pepeunlimited/authorization-twirp/rpc"
	"github.com/pepeunlimited/microservice-kit/jwt"
	"github.com/pepeunlimited/microservice-kit/rpcz"
	rpc2 "github.com/pepeunlimited/users/rpc"
	"github.com/twitchtv/twirp"
	"log"
	"time"
)

type AuthorizationServer struct {
	validator 	validator.AuthorizationServerValidator
	userService rpc2.UserService
	jwt 		jwt.JWT
}

func (server AuthorizationServer) RefreshAccessToken(ctx context.Context, params *rpc.RefreshAccessTokenParams) (*rpc.RefreshAccessTokenResponse, error) {
	return nil, nil
}

func (server AuthorizationServer) VerifyAccessToken(ctx context.Context, params *rpc.VerifyAccessTokenParams) (*rpc.VerifyAccessTokenResponse, error) {
	err := server.validator.VerifyAccessToken(params)
	if err != nil {
		return nil, err
	}
	claims, err := server.jwt.VerifyCustomClaims(params.AccessToken)
	if err != nil {
		switch err {
		case jwt.ErrExpired:
			return nil, twirp.NewError(twirp.Unauthenticated, err.Error()).WithMeta(rpcz.Reason, rpc.JwtExpired)
		case jwt.ErrMalformed:
			return nil, twirp.NewError(twirp.Malformed, err.Error()).WithMeta(rpcz.Reason, rpc.JwtMalformed)
		}
		return nil, twirp.NewError(twirp.Internal, err.Error()).WithMeta(rpcz.Reason, rpc.JwtUnknownError)
	}
	resp := &rpc.VerifyAccessTokenResponse{
		Username: claims.Username,
		Roles:    claims.Roles,
	}
	if claims.Email != nil {
		resp.Email = *claims.Email
	}
	if claims.UserId != nil {
		resp.UserId = *claims.UserId
	}
	return resp, nil
}

func (server AuthorizationServer) SignIn(ctx context.Context, params *rpc.SignInParams) (*rpc.SignInResponse, error) {
	log.Printf("sign-in: %s", params)
	err := server.validator.SignIn(params)
	if err != nil {
		return nil, err
	}
	// verify does the user exist and etc from users-service
	user, err := server.userService.VerifySignIn(ctx, &rpc2.VerifySignInParams{
		Username: params.Username,
		Password: params.Password,
	})
	if err != nil {
		return nil, err
	}
	accessToken, err := server.jwt.SignIn(30*time.Minute, user.Username, &user.Email, user.Roles, &user.Id)
	if err != nil {
		return nil, err
	}
	return &rpc.SignInResponse{
		AccessToken:          accessToken,
		RefreshToken:         "",
	}, nil
}

func NewAuthorizationServer(secret string, userService rpc2.UserService) AuthorizationServer {
	return AuthorizationServer{
		userService: 	userService,
		validator: 		validator.NewAuthorizationServerValidator(),
		jwt: 			jwt.NewJWT([]byte(secret)),
	}
}