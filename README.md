# HarbourJwt
JWT Implementation for Harbour

A simple library to work with JSON Web Token and JSON Web Signature for Harbour language

## Installation

Package is available on [GitHub](https://github.com/matteobaccan/HarbourJwt/blob/main/lib/jwt.hrb),

```shell
wget https://github.com/matteobaccan/HarbourJwt/blob/main/lib/jwt.hrb?raw=true
```

## Documentation
JWT is a class library that can allow you to generate and validate JWT tokens

### Token generation
To create  a token you must 

1. Load jwt,hrb library

```
LOCAL handle := hb_hrbLoad( "jwt.hrb" )
```

2. Create an empty JWT object

```
LOCAL oJWT 
LOCAL cToken
   
// Object
oJWT := &("JWT():new()")
```

3. Configure a valid header, setting Type = JWT and an available Algorithm. At the moment the Algorithms available are: HS256, HS384, and HS512

```
// Header
oJWT:setAlgorithm("HS256")
oJWT:setType("JWT")
```

4. Load a payload. The properties permitted in a payload are: 

```
METHOD SetIssuer( cIssuer )
METHOD SetSubject( cSubject )
METHOD SetAudience( cAudience )
METHOD SetExpration( nExpiration )
METHOD SetNotBefore( nNotBefore )
METHOD SetIssuedAt( nIssuedAt )
METHOD SetJWTId( cJWTId )
```

A simple payload can be formed by: Subject, Name, and IssueAt

```
// Payload
oJWT:setSubject("1234567890")
oJWT:setPayloadData("name", "John Doe")
oJWT:setIssuedAt(1516239022)
```

5. Finally you must indicate a secret

```
// Secret
oJWT:setSecret("your-256-bit-secret")
```

6. Now you can get a token

```
// Get Token
cToken = oJWT:Encode()
```

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Token verification
Token verifications are also simple

1. Load jwt.hrb library

```
LOCAL handle := hb_hrbLoad( "jwt.hrb" )
```

2. Create an empty JWT object

```
LOCAL oJWT 

// Object
oJWT := &("JWT():new()")
```

3. Verify the token

```
oJWT:SetSecret("MySecret")
oJWT:Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hdHRlbyBCYWNjYW4iLCJpYXQiOjE1MTYyMzkwMjJ9.YR8QF52kgj0owYlP9TkEy_lNhC-Qdq38tqNNNqpvpK0")
```

Verify return a .T. if the token is valid. Otherwise with

```
oJWT:GetError()
```
you can get the decode error

## Contribution
Feel free to update this code with a new PR
