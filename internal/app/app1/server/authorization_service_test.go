package server

import (
	"context"
	"fmt"
	rpc2 "github.com/pepeunlimited/authorization-twirp/rpc"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/pepeunlimited/users/rpc"
	"github.com/twitchtv/twirp"
	"log"
	"testing"
	"time"
)

var secret string = "s3cr3t"

func TestAuthorizationServer_SignIn(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock(nil, false))
	ctx := context.TODO()
	resp0, err := server.SignIn(ctx, &rpc2.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if validator.IsEmpty(resp0.Token) {
		t.FailNow()
	}
	resp1, err := server.Verify(ctx, &rpc2.VerifyParams{Token:resp0.Token})
	log.Print(resp1)
}

func TestAuthorizationServer_SignInError(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock([]error{fmt.Errorf("custom-error")}, false))
	ctx := context.TODO()
	_, err := server.SignIn(ctx, &rpc2.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err == nil {
		t.FailNow()
	}
}

func TestAuthorizationServer_VerifyExpired(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock(nil, false))
	ctx := context.TODO()
	token, err := server.jwt.SignIn(1*time.Second, "username", nil, []string{"User"}, nil)
	time.Sleep(2 * time.Second)
	_, err = server.Verify(ctx, &rpc2.VerifyParams{Token: token})
	if err == nil {
		t.FailNow()
	}
	if err.(twirp.Error).Meta("reason") != "jwt_expired" {
		t.FailNow()
	}
}

func TestAuthorizationServer_VerifyMalformed(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock(nil, false))
	ctx := context.TODO()
	token := "eyJhbGciOiJIUzI1NIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InNpaW1vbyIsImtYWlsIjoic2ltb29AZ21haWwuY29tIiwicm9sZXMiOlsidXNlciJdLCJ1c2VyX2lkIjozLCJleHAiOjE1Nzc2MTczOTR9.AC7mkWENKOwHdZWkbD0QaBR1mMhxR1mo8PKztwQ47qA"
	_, err := server.Verify(ctx, &rpc2.VerifyParams{Token: token})
	if err == nil {
		t.FailNow()
	}
	if err.(twirp.Error).Meta("reason") != "jwt_malformed" {
		t.Error(err)
		t.FailNow()
	}
}

func TestAuthorizationServer_VerifyCantAccessUserService(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock([]error{fmt.Errorf("asd")}, false))
	ctx := context.TODO()
	_, err := server.SignIn(ctx, &rpc2.SignInParams{
		Username: "a",
		Password: "b",
	})
	if err == nil {
		t.FailNow()
	}
	if err.Error() != "asd" {
		t.FailNow()
	}
}

func TestAuthorizationServer_SignInCantAccessUserService(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock([]error{fmt.Errorf("asd")}, false))
	ctx := context.TODO()
	token,_ := server.jwt.SignIn(2*time.Second, "username", nil, []string{"User"}, nil)
	_, err := server.Verify(ctx, &rpc2.VerifyParams{Token:token})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

