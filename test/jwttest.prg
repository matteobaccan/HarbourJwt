#include "hbclass.ch"
#include "hbhrb.ch"

FUNCTION Main
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

// Default token denerated by https://jwt.io/
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
AssertEquals(cToken,"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg", oJWT:getError() )

// Token validation
AssertEquals( oJWT:Verify("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg"), .T., oJWT:getError() )

oJWT:SetIssuer('Matteo')
cToken = oJWT:Encode()
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )
AssertEquals( oJWT:Decode(cToken), .T., oJWT:getError() )

// Verify is false because secret is reset by Decode
AssertEquals( oJWT:Verify(cToken), .F., oJWT:getError() )

// Recover secret
oJWT:setSecret("your-512-bit-secret")
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )

// test different odience
oJWT:SetSubject("new subject")
AssertEquals( oJWT:Verify(cToken), .F., oJWT:getError() )
oJWT:SetSubject("1234567890")
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )

// test different odience
oJWT:SetAudience("new odience")
AssertEquals( oJWT:Verify(cToken), .F., oJWT:getError() )
oJWT:SetAudience(NIL)
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )

// Expired token
oJWT:SetExpration( oJWT:GetSeconds()-1 )
cToken = oJWT:Encode()
AssertEquals( oJWT:Verify(cToken), .F., oJWT:getError() )
oJWT:SetExpration( oJWT:GetSeconds()+1 )
cToken = oJWT:Encode()
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )

// NotBefore
oJWT:SetNotBefore( oJWT:GetSeconds()+2 )
cToken = oJWT:Encode()
AssertEquals( oJWT:Verify(cToken), .F., oJWT:getError() )
oJWT:SetNotBefore( oJWT:GetSeconds() )
cToken = oJWT:Encode()
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )

// Issued at
oJWT:SetIssuedAt( oJWT:GetSeconds()+1 )
cToken = oJWT:Encode()
AssertEquals( oJWT:Verify(cToken), .F., oJWT:getError() )
oJWT:SetIssuedAt( oJWT:GetSeconds() )
cToken = oJWT:Encode()
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )

// JWTId
oJWT:SetJWTId("ID:100")
AssertEquals( oJWT:Verify(cToken), .F., oJWT:getError() )
oJWT:SetJWTId(NIL)
AssertEquals( oJWT:Verify(cToken), .T., oJWT:getError() )

// Token decode
AssertEquals( oJWT:Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hdHRlbyBCYWNjYW4iLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyMn0.0T90m9fq8aOuiNbycTJxCf7BiQLw9xWXxe58-zV4RpY"), .T., oJWT:getError() )

// Check internal data exposion
AssertEquals(oJWT:GetHeader()['alg'], oJWT:GetAlgorithm(), oJWT:getError() )
oJWT:GetHeader()['alg'] := 'dddd'
AssertEquals(oJWT:GetHeader()['alg'], oJWT:GetAlgorithm(), oJWT:getError() )

// Versione 
AssertEquals(oJWT:GetVersion(), "1.0.1" )

hb_hrbUnload( handle )

RETU NIL


function AssertEquals( uValue, uExpected, cMessage )
   IF uValue==uExpected
      ? "OK - data verified"
   ELSE
      ? "KO - invalid data"
      ? "Value   :", uValue
      ? "Expected:", uExpected
      IF cMessage!=NIL .AND. !EMPTY(cMessage)
         ? cMessage
      ENDIF
   ENDIF
retu nil