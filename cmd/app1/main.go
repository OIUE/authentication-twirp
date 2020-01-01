package main

import (
	"github.com/pepeunlimited/authorization-twirp/internal/app/app1/server"
	"github.com/pepeunlimited/authorization-twirp/rpc"
	"github.com/pepeunlimited/microservice-kit/headers"
	"github.com/pepeunlimited/microservice-kit/jwt"
	"github.com/pepeunlimited/microservice-kit/middleware"
	"github.com/pepeunlimited/microservice-kit/misc"
	rpc2 "github.com/pepeunlimited/users/rpc"
	"log"
	"net/http"
)

const (
	Version = "0.1.1.1"
)

func main() {
	log.Printf("Starting the authorization-twirp... version=[%v]", Version)

	secret := misc.GetEnv(jwt.SECRET_KEY, "v3ry-s3cr3t-k3y")
	usersAddress := misc.GetEnv(rpc2.RpcUsersHost, "http://localhost:8080")

	as := rpc.NewAuthorizationServiceServer(server.NewAuthorizationServer(secret,
		rpc2.NewUserServiceProtobufClient(usersAddress,http.DefaultClient)), nil)
	mux := http.NewServeMux()
	mux.Handle(as.PathPrefix(), middleware.Adapt(as, headers.Authorizationz()))

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Panic(err)
	}
}