#include "hbclass.ch"
#include "hbhrb.ch"

FUNCTION Main
LOCAL handle := hb_hrbLoad( "../lib/jwt.hrb" )
LOCAL oJWT, oJWTVerify
LOCAL cToken

? "JWTCreate"

// JWT (JSON Web Token) is created server side, and then sent to the client (normally after an API call is made).
// The client then sends the JWT back to the server for authentication.

// -----------------------------------------
// Server creation schema : you can use this code inside a mod_harbour service
// -----------------------------------------

// Creare a new Object
oJWT := &("JWT():new()")

// Add Header for identify the kind of token
oJWT:setAlgorithm("HS256")
oJWT:setType("JWT")

// Create Payload
oJWT:setSubject("1234567890")

// You can put all you wants inside the payload
oJWT:setPayloadData("id", "my name")
oJWT:setPayloadData("exp" , 30) // tiempo en segundos que expira el token
oJWT:setPayloadData("session" , "123045678901234567890")

// Issued NOW
oJWT:setIssuedAt( oJWT:GetSeconds() )

// Expire after 5 seconds
oJWT:SetExpration( oJWT:GetSeconds()+5 )

// Secret - This value is know server side: you can put all you wants
oJWT:setSecret("your-256-bit-secret")

// Now you can encode the token and send cToken from server side to client side
cToken = oJWT:Encode()
// -----------------------------------------



// -----------------------------------------
// Client store the token and send it to the server for every call, the server 
// receive the token and must validate it
// -----------------------------------------
// This is the standard way to give the token from client to server
// Authorization: Bearer <token>

// for example
// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c


// -----------------------------------------
// Server receive the header, get the token and validate it
oJWTverify := &("JWT():new()")

// Add Header for identify the kind of token
oJWTverify:setAlgorithm("HS256")
oJWTverify:setType("JWT")

// Set the same subject
oJWTverify:setSubject("1234567890")

// Secret - This value is know only server side
oJWTverify:setSecret("your-256-bit-secret")
IF oJWTverify:Verify(cToken)
   ? "OK - valid"
ELSE
   ? "ERROR"
   ? oJWTVerify:getError()
ENDIF

// 6 seconds later (after 5 seconds of expiration)
INKEY(6)

// Now thest agai the token
IF oJWTverify:Verify(cToken)
   ? "OK"
ELSE
   ? "ERROR - expired"
   ? oJWTVerify:getError()
ENDIF

hb_hrbUnload( handle )

RETU NIL
