package server

import (
	"github.com/pepeunlimited/authorization-twirp/internal/app/app1/validator"
)

type AuthorizationServer struct {
	validator validator.AuthorizationServerValidator
}


func NewTodoServer() AuthorizationServer {

	return AuthorizationServer{
		validator: validator.NewAuthorizationServerValidator(),
	}
}