#include "hbclass.ch"
#include "hbhrb.ch"

function main
LOCAL handle := hb_hrbLoad( "../lib/jwt.hrb" )
LOCAL oJWT 
LOCAL cToken
   
// Object
oJWT := &("JWT():new()")

// Header
oJWT:setAlgorithm("HS256")
oJWT:setType("JWT")

// Payload
oJWT:setSubject("1234567890")
oJWT:setPayloadData("name", "John Doe")
oJWT:setIssuedAt(1516239022)

// Secret
oJWT:setSecret("your-256-bit-secret")

cToken = oJWT:Encode()

AssertEquals(cToken,"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

// Test HS384
oJWT:setAlgorithm("HS384")
oJWT:setSecret("your-384-bit-secret")
cToken = oJWT:Encode()
AssertEquals(cToken,"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ")

// Test HS512
oJWT:setAlgorithm("HS512")
oJWT:setSecret("your-512-bit-secret")
cToken = oJWT:Encode()
AssertEquals(cToken,"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg")

// Test none
oJWT:setAlgorithm("none")
cToken = oJWT:Encode()
AssertEquals(cToken,"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg")

// Token validation
AssertEquals( oJWT:Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hdHRlbyBCYWNjYW4iLCJpYXQiOjE1MTYyMzkwMjJ9.YR8QF52kgj0owYlP9TkEy_lNhC-Qdq38tqNNNqpvpK0", "MySecret"), .T. )

// Token validation
AssertEquals( oJWT:Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hdHRlbyBCYWNjYW4iLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyMn0.0T90m9fq8aOuiNbycTJxCf7BiQLw9xWXxe58-zV4RpY", "MySecret"), .F. )
? oJWT:GetError()

hb_hrbUnload( handle )

RETU NIL


function AssertEquals( uValue, uExpected )
   IF uValue==uExpected
      ? "OK - signature verified"
   ELSE
      ? "KO - invalid signature"
      ? "Value   :", uValue
      ? "Expected:", uExpected
   ENDIF
retu nil