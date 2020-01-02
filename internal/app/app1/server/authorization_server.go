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
	validator 		validator.AuthorizationServerValidator
	userService 	rpc2.UserService
	accessToken 	jwt.JWT
	refreshToken 	jwt.JWT
}

const (
	accessTokenExp 		time.Duration = 10*time.Minute
	refreshTokenExp 	time.Duration = (24*time.Hour) * 2 // 31
	newRefreshToken     time.Duration = (24*time.Hour) * 1 // 7
)

func (server AuthorizationServer) RefreshAccessToken(ctx context.Context, params *rpc.RefreshAccessTokenParams) (*rpc.RefreshAccessTokenResponse, error) {
	if err := server.validator.RefreshAccessToken(params); err != nil {
		return nil, err
	}
	claims, err := server.refreshToken.VerifyCustomClaims(params.RefreshToken)
	if err != nil {
		return nil, server.isRefreshTokenError(err)
	}
	// TODO: implement access token revoke (blacklist)
	accessToken, err := server.accessToken.SignIn(accessTokenExp, claims.Username, claims.Email, claims.Roles, claims.UserId)
	if err != nil {
		log.Print("authorization-twirp: unknown error during accessToken: "+err.Error())
		return nil, twirp.InternalErrorWith(err)
	}
	resp := &rpc.RefreshAccessTokenResponse{AccessToken:  accessToken}
	// new refresh_token if the refresh token expires in 7d's
	if server.isRefreshToken(time.Unix(claims.ExpiresAt, 0), newRefreshToken) {
		refreshToken, err := server.refreshToken.SignIn(refreshTokenExp, claims.Username, claims.Email, claims.Roles, claims.UserId)
		if err != nil {
			log.Print("authorization-twirp: unknown error during accessToken: "+err.Error())
			return nil, twirp.InternalErrorWith(err)
		}
		resp.RefreshToken = refreshToken
	}
	return resp, nil
}

func (server AuthorizationServer) isRefreshToken(expiresAt time.Time, before time.Duration) bool {
	newRefreshTokenAt := expiresAt.UTC().Add(-before)
	//log.Print(newRefreshTokenAt)
	//log.Print(time.Date(2020, 1,25, 22,28,0,0, time.UTC).After(expiresAt))
	return time.Now().UTC().After(newRefreshTokenAt)
}

func (server AuthorizationServer) VerifyAccessToken(ctx context.Context, params *rpc.VerifyAccessTokenParams) (*rpc.VerifyAccessTokenResponse, error) {
	err := server.validator.VerifyAccessToken(params)
	if err != nil {
		return nil, err
	}
	claims, err := server.accessToken.VerifyCustomClaims(params.AccessToken)
	if err != nil {
		return nil, server.isAccessTokenError(err)
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


func (server AuthorizationServer) isRefreshTokenError(error error) error {
	return server.isJwtError(error, rpc.RefreshTokenExpired, rpc.RefreshTokenMalformed, rpc.RefreshTokenUnknownError)
}

func (server AuthorizationServer) isAccessTokenError(error error) error {
	return server.isJwtError(error, rpc.AccessTokenExpired, rpc.AccessTokenMalformed, rpc.AccessTokenUnknownError)
}

func (server AuthorizationServer) isJwtError(error error, expired string, malformed string, unknown string) error {
	switch error {
	case jwt.ErrExpired:
		return twirp.NewError(twirp.Unauthenticated, error.Error()).WithMeta(rpcz.Reason, expired)
	case jwt.ErrMalformed:
		return twirp.NewError(twirp.Malformed, error.Error()).WithMeta(rpcz.Reason, malformed)
	}
	return twirp.NewError(twirp.Internal, error.Error()).WithMeta(rpcz.Reason, unknown)
}

func (server AuthorizationServer) SignIn(ctx context.Context, params *rpc.SignInParams) (*rpc.SignInResponse, error) {
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
	accessToken, err := server.accessToken.SignIn(accessTokenExp, user.Username, &user.Email, user.Roles, &user.Id)
	if err != nil {
		log.Print("authorization-twirp: unknown error during accessToken: "+err.Error())
		return nil, twirp.InternalErrorWith(err)
	}
	// refresh token is valid 31d's
	refreshToken, err := server.refreshToken.SignIn(refreshTokenExp, user.Username, &user.Email, user.Roles, &user.Id)
	if err != nil {
		log.Print("authorization-twirp: unknown error during refreshToken: "+err.Error())
		return nil, twirp.InternalErrorWith(err)
	}
	return &rpc.SignInResponse{
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
	}, nil
}

func NewAuthorizationServer(accessTokenSecret string, refreshTokenSecret string, userService rpc2.UserService) AuthorizationServer {
	return AuthorizationServer{
		userService: 	userService,
		validator: 		validator.NewAuthorizationServerValidator(),
		accessToken: 	jwt.NewJWT([]byte(accessTokenSecret)),
		refreshToken: 	jwt.NewJWT([]byte(refreshTokenSecret)),
	}
}