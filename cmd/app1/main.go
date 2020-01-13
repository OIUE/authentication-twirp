package main

import (
	"github.com/pepeunlimited/authorization-twirp/internal/app/app1/server"
	"github.com/pepeunlimited/authorization-twirp/rpcauthorization"
	"github.com/pepeunlimited/microservice-kit/headers"
	"github.com/pepeunlimited/microservice-kit/jwt"
	"github.com/pepeunlimited/microservice-kit/middleware"
	"github.com/pepeunlimited/microservice-kit/misc"
	rpc2 "github.com/pepeunlimited/users/rpc"
	"log"
	"net/http"
)

const (
	Version = "0.1.2.2"
)

func main() {
	log.Printf("Starting the authorization-twirp... version=[%v]", Version)

	accessTokenSecret := misc.GetEnv(jwt.AccessTokenSecretKey, "v3ry-s3cr3t-k3y-666")
	refreshTokenSecret := misc.GetEnv(jwt.RefreshTokenSecretKey, "v3ry-s3cr3t-k3y-999")
	usersAddress := misc.GetEnv(rpc2.RpcUsersHost, "http://localhost:8080")

	as := rpcauthorization.NewAuthorizationServiceServer(
		server.NewAuthorizationServer(accessTokenSecret,
		refreshTokenSecret,
		rpc2.NewUserServiceProtobufClient(usersAddress,http.DefaultClient)),
		nil)
	mux := http.NewServeMux()
	mux.Handle(as.PathPrefix(), middleware.Adapt(as, headers.Authorizationz()))

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Panic(err)
	}
}