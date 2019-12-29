// Code generated by protoc-gen-go. DO NOT EDIT.
// source: authorization.proto

package rpc

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	_ "github.com/golang/protobuf/ptypes/empty"
	_ "github.com/golang/protobuf/ptypes/wrappers"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type SignInParams struct {
	Username             string   `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password             string   `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignInParams) Reset()         { *m = SignInParams{} }
func (m *SignInParams) String() string { return proto.CompactTextString(m) }
func (*SignInParams) ProtoMessage()    {}
func (*SignInParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dbbe58d1e51a797, []int{0}
}

func (m *SignInParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignInParams.Unmarshal(m, b)
}
func (m *SignInParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignInParams.Marshal(b, m, deterministic)
}
func (m *SignInParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignInParams.Merge(m, src)
}
func (m *SignInParams) XXX_Size() int {
	return xxx_messageInfo_SignInParams.Size(m)
}
func (m *SignInParams) XXX_DiscardUnknown() {
	xxx_messageInfo_SignInParams.DiscardUnknown(m)
}

var xxx_messageInfo_SignInParams proto.InternalMessageInfo

func (m *SignInParams) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *SignInParams) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type SignInResponse struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	RefreshToken         string   `protobuf:"bytes,2,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignInResponse) Reset()         { *m = SignInResponse{} }
func (m *SignInResponse) String() string { return proto.CompactTextString(m) }
func (*SignInResponse) ProtoMessage()    {}
func (*SignInResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dbbe58d1e51a797, []int{1}
}

func (m *SignInResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignInResponse.Unmarshal(m, b)
}
func (m *SignInResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignInResponse.Marshal(b, m, deterministic)
}
func (m *SignInResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignInResponse.Merge(m, src)
}
func (m *SignInResponse) XXX_Size() int {
	return xxx_messageInfo_SignInResponse.Size(m)
}
func (m *SignInResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SignInResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SignInResponse proto.InternalMessageInfo

func (m *SignInResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *SignInResponse) GetRefreshToken() string {
	if m != nil {
		return m.RefreshToken
	}
	return ""
}

type RefreshParams struct {
	RefreshToken         string   `protobuf:"bytes,1,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RefreshParams) Reset()         { *m = RefreshParams{} }
func (m *RefreshParams) String() string { return proto.CompactTextString(m) }
func (*RefreshParams) ProtoMessage()    {}
func (*RefreshParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dbbe58d1e51a797, []int{2}
}

func (m *RefreshParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RefreshParams.Unmarshal(m, b)
}
func (m *RefreshParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RefreshParams.Marshal(b, m, deterministic)
}
func (m *RefreshParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RefreshParams.Merge(m, src)
}
func (m *RefreshParams) XXX_Size() int {
	return xxx_messageInfo_RefreshParams.Size(m)
}
func (m *RefreshParams) XXX_DiscardUnknown() {
	xxx_messageInfo_RefreshParams.DiscardUnknown(m)
}

var xxx_messageInfo_RefreshParams proto.InternalMessageInfo

func (m *RefreshParams) GetRefreshToken() string {
	if m != nil {
		return m.RefreshToken
	}
	return ""
}

type RefreshResponse struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RefreshResponse) Reset()         { *m = RefreshResponse{} }
func (m *RefreshResponse) String() string { return proto.CompactTextString(m) }
func (*RefreshResponse) ProtoMessage()    {}
func (*RefreshResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dbbe58d1e51a797, []int{3}
}

func (m *RefreshResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RefreshResponse.Unmarshal(m, b)
}
func (m *RefreshResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RefreshResponse.Marshal(b, m, deterministic)
}
func (m *RefreshResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RefreshResponse.Merge(m, src)
}
func (m *RefreshResponse) XXX_Size() int {
	return xxx_messageInfo_RefreshResponse.Size(m)
}
func (m *RefreshResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_RefreshResponse.DiscardUnknown(m)
}

var xxx_messageInfo_RefreshResponse proto.InternalMessageInfo

func (m *RefreshResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type VerifyParams struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VerifyParams) Reset()         { *m = VerifyParams{} }
func (m *VerifyParams) String() string { return proto.CompactTextString(m) }
func (*VerifyParams) ProtoMessage()    {}
func (*VerifyParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dbbe58d1e51a797, []int{4}
}

func (m *VerifyParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyParams.Unmarshal(m, b)
}
func (m *VerifyParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyParams.Marshal(b, m, deterministic)
}
func (m *VerifyParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyParams.Merge(m, src)
}
func (m *VerifyParams) XXX_Size() int {
	return xxx_messageInfo_VerifyParams.Size(m)
}
func (m *VerifyParams) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyParams.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyParams proto.InternalMessageInfo

type VerifyResponse struct {
	Username             string   `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Email                string   `protobuf:"bytes,2,opt,name=email,proto3" json:"email,omitempty"`
	UserId               int64    `protobuf:"varint,3,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Roles                []string `protobuf:"bytes,4,rep,name=roles,proto3" json:"roles,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VerifyResponse) Reset()         { *m = VerifyResponse{} }
func (m *VerifyResponse) String() string { return proto.CompactTextString(m) }
func (*VerifyResponse) ProtoMessage()    {}
func (*VerifyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dbbe58d1e51a797, []int{5}
}

func (m *VerifyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyResponse.Unmarshal(m, b)
}
func (m *VerifyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyResponse.Marshal(b, m, deterministic)
}
func (m *VerifyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyResponse.Merge(m, src)
}
func (m *VerifyResponse) XXX_Size() int {
	return xxx_messageInfo_VerifyResponse.Size(m)
}
func (m *VerifyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyResponse proto.InternalMessageInfo

func (m *VerifyResponse) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *VerifyResponse) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *VerifyResponse) GetUserId() int64 {
	if m != nil {
		return m.UserId
	}
	return 0
}

func (m *VerifyResponse) GetRoles() []string {
	if m != nil {
		return m.Roles
	}
	return nil
}

func init() {
	proto.RegisterType((*SignInParams)(nil), "pepeunlimited.authorization.SignInParams")
	proto.RegisterType((*SignInResponse)(nil), "pepeunlimited.authorization.SignInResponse")
	proto.RegisterType((*RefreshParams)(nil), "pepeunlimited.authorization.RefreshParams")
	proto.RegisterType((*RefreshResponse)(nil), "pepeunlimited.authorization.RefreshResponse")
	proto.RegisterType((*VerifyParams)(nil), "pepeunlimited.authorization.VerifyParams")
	proto.RegisterType((*VerifyResponse)(nil), "pepeunlimited.authorization.VerifyResponse")
}

func init() { proto.RegisterFile("authorization.proto", fileDescriptor_1dbbe58d1e51a797) }

var fileDescriptor_1dbbe58d1e51a797 = []byte{
	// 356 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x4d, 0x4f, 0xc2, 0x40,
	0x14, 0x4c, 0xa9, 0x14, 0x7d, 0x01, 0x4c, 0x56, 0x12, 0x9b, 0x92, 0x18, 0x52, 0x0f, 0xe2, 0x47,
	0x4a, 0xa2, 0xfe, 0x01, 0x3d, 0x98, 0x10, 0x2f, 0xa6, 0x18, 0x0f, 0x5e, 0x60, 0xa1, 0x0f, 0xd8,
	0xd8, 0x76, 0xd7, 0xdd, 0x56, 0x82, 0x7f, 0xce, 0xbf, 0x66, 0xca, 0xd6, 0x06, 0xd4, 0x14, 0x8e,
	0xb3, 0x33, 0xf3, 0xfa, 0xde, 0x4c, 0xe1, 0x88, 0xa6, 0xc9, 0x9c, 0x4b, 0xf6, 0x49, 0x13, 0xc6,
	0x63, 0x4f, 0x48, 0x9e, 0x70, 0xd2, 0x16, 0x28, 0x30, 0x8d, 0x43, 0x16, 0xb1, 0x04, 0x03, 0x6f,
	0x43, 0xe2, 0xb4, 0x67, 0x9c, 0xcf, 0x42, 0xec, 0xad, 0xa4, 0xe3, 0x74, 0xda, 0xc3, 0x48, 0x24,
	0x4b, 0xed, 0x74, 0x4e, 0x7e, 0x93, 0x0b, 0x49, 0x85, 0x40, 0xa9, 0x34, 0xef, 0x3e, 0x40, 0x7d,
	0xc0, 0x66, 0x71, 0x3f, 0x7e, 0xa2, 0x92, 0x46, 0x8a, 0x38, 0xb0, 0x9f, 0x2a, 0x94, 0x31, 0x8d,
	0xd0, 0x36, 0x3a, 0x46, 0xf7, 0xc0, 0x2f, 0x70, 0xc6, 0x09, 0xaa, 0xd4, 0x82, 0xcb, 0xc0, 0xae,
	0x68, 0xee, 0x07, 0xbb, 0x8f, 0xd0, 0xd4, 0x73, 0x7c, 0x54, 0x82, 0xc7, 0x0a, 0x49, 0x0b, 0xaa,
	0x09, 0x7f, 0xc3, 0x38, 0x1f, 0xa3, 0x01, 0x39, 0x85, 0x86, 0xc4, 0xa9, 0x44, 0x35, 0x1f, 0x6a,
	0x56, 0x0f, 0xaa, 0xe7, 0x8f, 0xcf, 0xd9, 0x9b, 0x7b, 0x0b, 0x0d, 0x5f, 0xe3, 0x7c, 0xab, 0x3f,
	0x2e, 0xe3, 0x1f, 0xd7, 0x19, 0x1c, 0xe6, 0xae, 0xf2, 0x1d, 0xdc, 0x26, 0xd4, 0x5f, 0x50, 0xb2,
	0xe9, 0x52, 0x4f, 0x77, 0xdf, 0xa1, 0xa9, 0x71, 0xe1, 0x2b, 0x4b, 0xa1, 0x05, 0x55, 0x8c, 0x28,
	0x0b, 0xf3, 0xcd, 0x35, 0x20, 0xc7, 0x50, 0xcb, 0x14, 0x43, 0x16, 0xd8, 0x66, 0xc7, 0xe8, 0x9a,
	0xbe, 0x95, 0xc1, 0x7e, 0x90, 0xc9, 0x25, 0x0f, 0x51, 0xd9, 0x7b, 0x1d, 0x33, 0x93, 0xaf, 0xc0,
	0xf5, 0x57, 0x05, 0x5a, 0x77, 0xeb, 0x2d, 0x0e, 0x50, 0x7e, 0xb0, 0x09, 0x92, 0x11, 0x58, 0x3a,
	0x47, 0x72, 0xee, 0x95, 0x94, 0xee, 0xad, 0x97, 0xe6, 0x5c, 0xee, 0x20, 0x2d, 0x6e, 0x9b, 0x40,
	0x2d, 0x8f, 0x89, 0x5c, 0x94, 0xfa, 0x36, 0x2a, 0x70, 0xae, 0x76, 0xd1, 0x16, 0x1f, 0x19, 0x81,
	0xa5, 0x23, 0xdd, 0x72, 0xc6, 0x7a, 0x0f, 0x5b, 0xce, 0xd8, 0xac, 0xe8, 0xbe, 0xfa, 0x6a, 0x4a,
	0x31, 0x19, 0x5b, 0xab, 0xdf, 0xf8, 0xe6, 0x3b, 0x00, 0x00, 0xff, 0xff, 0xb3, 0x6c, 0xff, 0x9e,
	0x37, 0x03, 0x00, 0x00,
}
