package rpcauth

import (
	"github.com/pepeunlimited/microservice-kit/rpcz"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/twitchtv/twirp"
)

const (
	AccessTokenUnknownError 	= "access_token_unknown_error"
	AccessTokenExpired 			= "access_token_expired"
	AccessTokenMalformed		= "access_token_malformed"

	RefreshTokenUnknownError 	= "refresh_token_unknown_error"
	RefreshTokenExpired 		= "refresh_token_expired"
	RefreshTokenMalformed		= "refresh_token_malformed"
)

func IsReason(error twirp.Error, key string) bool {
	reason := error.Meta(rpcz.Reason)
	if validator.IsEmpty(reason) {
		return false
	}
	return reason == key
}