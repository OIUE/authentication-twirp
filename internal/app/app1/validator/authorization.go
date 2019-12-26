package validator

import (

)

type AuthorizationServerValidator struct {}


func NewAuthorizationServerValidator() AuthorizationServerValidator {
	return AuthorizationServerValidator{}
}

func (TodoServerValidator) CreateTodo(params *rpc.CreateTodoParams) error {
	return nil
}

func (TodoServerValidator) GetTodo(params *rpc.GetTodoParams) error {
	return nil
}

func (TodoServerValidator) UpdateTodo(params *rpc.UpdateTodoParams) error {
	return nil
}

func (TodoServerValidator) DeleteTodo(params *rpc.DeleteTodoParams) error {
	return nil
}