package server

import (
	"context"
	"fmt"
	rpc2 "github.com/pepeunlimited/authorization-twirp/rpc"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/pepeunlimited/users/rpc"
	"testing"
)

var secret string = "s3cr3t"

func TestAuthorizationServer_SignIn(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock(nil, false))
	resp, err := server.SignIn(context.TODO(), &rpc2.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if validator.IsEmpty(resp.Token) {
		t.FailNow()
	}
}

func TestAuthorizationServer_SignInError(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock([]error{fmt.Errorf("custom-error")}, false))
	resp, err := server.SignIn(context.TODO(), &rpc2.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if validator.IsEmpty(resp.Token) {
		t.FailNow()
	}
}