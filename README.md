# HarbourJwt

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/297af1f39d004d7992599ce45fcd3b6a)](https://www.codacy.com/gh/matteobaccan/HarbourJwt/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=matteobaccan/HarbourJwt&amp;utm_campaign=Badge_Grade)

JWT Implementation for Harbour

A simple library to work with JSON Web Token and JSON Web Signature for Harbour language.
You can find more information about JWT on the [official website](https://jwt.io).

Harbour JWT supports the following algorithms:

- HS256
- HS384
- HS512

<!--
    (CVE-2015-2951) The alg=none signature-bypass vulnerability
    (CVE-2016-10555) The RS/HS256 public key mismatch vulnerability
    (CVE-2018-0114) Key injection vulnerability
    (CVE-2019-20933/CVE-2020-28637) Blank password vulnerability
    (CVE-2020-28042) Null signature vulnerability
-->

## Installation

Package is available on [GitHub](https://github.com/matteobaccan/HarbourJwt/blob/main/lib/jwt.hrb),

```shell
wget https://raw.githubusercontent.com/matteobaccan/HarbourJwt/main/lib/jwt.hrb
```

## Documentation

JWT is a class library that can allow you to generate and validate JWT tokens

### Token generation

To create a token you must

1 Load jwt.hrb library

```xBase
LOCAL handle := hb_hrbLoad( "jwt.hrb" )
```

2 Create an empty JWT object

```xBase
LOCAL oJWT
LOCAL cToken

// Object
oJWT := &("JWT():new()")
```

3 Configure a valid header, setting Type = JWT and an available Algorithm.
   At the moment the Algorithms available are: HS256, HS384, and HS512

```xBase
// Header
oJWT:setAlgorithm("HS256")
oJWT:setType("JWT")
```

4 Load a payload. The properties permitted in a payload are:

```xBase
METHOD SetIssuer( cIssuer )
METHOD SetSubject( cSubject )
METHOD SetAudience( cAudience )
METHOD SetExpration( nExpiration )
METHOD SetNotBefore( nNotBefore )
METHOD SetIssuedAt( nIssuedAt )
METHOD SetJWTId( cJWTId )
```

A simple payload can be formed by: Subject, Name, and IssueAt

```xBase
// Payload
oJWT:setSubject("1234567890")
oJWT:setPayloadData("name", "John Doe")
oJWT:setIssuedAt(1516239022)
```

5 Finally you must indicate a secret

```xBase
// Secret
oJWT:setSecret("your-256-bit-secret")
```

6 Now you can get a token

```xBase
// Get Token
cToken = oJWT:Encode()
```

```Text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Token verification

Token verifications are also simple

1 Load jwt.hrb library

```xBase
LOCAL handle := hb_hrbLoad( "jwt.hrb" )
```

2 Create an empty JWT object

```xBase
LOCAL oJWT

// Object
oJWT := &("JWT():new()")
```

3 Verify the token

```xBase
oJWT:SetSecret("MySecret")
oJWT:Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hdHRlbyBCYWNjYW4iLCJpYXQiOjE1MTYyMzkwMjJ9.YR8QF52kgj0owYlP9TkEy_lNhC-Qdq38tqNNNqpvpK0")
```

Verify return a .T. if the token is valid. Otherwise with

```xBase
oJWT:GetError()
```

you can get the decode error

## Contribution

Feel free to update this code with a new PR
