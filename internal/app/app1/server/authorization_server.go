package server

import (
	"context"
	"github.com/pepeunlimited/authorization-twirp/internal/app/app1/validator"
	"github.com/pepeunlimited/authorization-twirp/rpc"
	"github.com/pepeunlimited/microservice-kit/jwt"
	"github.com/pepeunlimited/microservice-kit/rpcz"
	rpc2 "github.com/pepeunlimited/users/rpc"
	"github.com/twitchtv/twirp"
	"time"
)

type AuthorizationServer struct {
	validator 	validator.AuthorizationServerValidator
	userService rpc2.UserService
	jwt 		jwt.JWT
}

func (server AuthorizationServer) SignIn(ctx context.Context, params *rpc.SignInParams) (*rpc.SignInResponse, error) {
	err := server.validator.SignIn(params)
	if err != nil {
		return nil, err
	}
	// verify from users-service
	user, err := server.userService.VerifySignIn(ctx, &rpc2.VerifySignInParams{
		Username: params.Username,
		Password: params.Password,
	})
	if err != nil {
		return nil, err
	}
	token, err := server.jwt.SignIn(30*time.Minute, user.Username, &user.Email, user.Roles, &user.Id)
	if err != nil {
		return nil, err
	}
	return &rpc.SignInResponse{
		Token:                token,
		RefreshToken:         "",
	}, nil
}

func (server AuthorizationServer) Refresh(ctx context.Context, params *rpc.RefreshParams) (*rpc.RefreshResponse, error) {
	return nil, nil
}

func (server AuthorizationServer) Verify(ctx context.Context, params *rpc.VerifyParams) (*rpc.VerifyResponse, error) {
	err := server.validator.Verify(params)
	if err != nil {
		return nil, err
	}
	claims, err := server.jwt.VerifyCustomClaims(params.Token)
	if err != nil {
		switch err {
		case jwt.ErrExpired:
			return nil, twirp.NewError(twirp.Internal, err.Error()).WithMeta(rpcz.Reason, rpc.JwtExpired)
		case jwt.ErrMalformed:
			return nil, twirp.NewError(twirp.Internal, err.Error()).WithMeta(rpcz.Reason, rpc.JwtMalformed)
		}
		return nil, twirp.NewError(twirp.Internal, err.Error()).WithMeta(rpcz.Reason, rpc.JwtUnknownError)
	}
	return &rpc.VerifyResponse{
		Username:             claims.Username,
		Email:                *claims.Email,
		UserId:               *claims.UserId,
		Roles:                claims.Roles,
	}, nil
}

func NewAuthorizationServer(secret string, userService rpc2.UserService) AuthorizationServer {
	return AuthorizationServer{
		userService: 	userService,
		validator: 		validator.NewAuthorizationServerValidator(),
		jwt: 			jwt.NewJWT([]byte(secret)),
	}
}