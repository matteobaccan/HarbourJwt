/*
 * Copyright (c) 2019 Matteo Baccan
 * https://www.baccan.it
 *
 * Distributed under the GPL v3 software license, see the accompanying
 * file LICENSE or http://www.gnu.org/licenses/gpl.html.
 *
 */
/**
 * JWT Implementation
 *
 * https://datatracker.ietf.org/doc/html/rfc7519
 *
 */
#include "hbclass.ch"

CLASS JWT

HIDDEN:

  CLASSDATA cSecret
  CLASSDATA aHeader
  CLASSDATA aPayload
  CLASSDATA cError

  METHOD Base64UrlEncode( cData )
  METHOD Base64UrlDecode( cData )
  METHOD ByteToString( cData ) 
  METHOD GetSignature( cHeader, cPayload, cSecret, cAlgorithm )

EXPORTED:

  METHOD New() CONSTRUCTOR

  // Header
  METHOD SetType( cType )
  METHOD GetType()                          INLINE ::aHeader[ 'typ' ]
  METHOD SetContentType( cContentType )     INLINE ::aHeader[ 'cty' ] :=  cContentType
  METHOD GetContentType()                   INLINE ::aHeader[ 'cty' ]
  METHOD SetAlgorithm( cAlgorithm )
  METHOD GetAlgorithm()                     INLINE ::aHeader[ 'alg' ]

  // Payload
  METHOD SetIssuer( cIssuer )               INLINE ::aPayload[ 'iss' ] := cIssuer
  METHOD GetIssuer()                        INLINE ::aPayload[ 'iss' ] 
  METHOD SetSubject( cSubject )             INLINE ::aPayload[ 'sub' ] := cSubject
  METHOD GetSubject()                       INLINE ::aPayload[ 'sub' ] 
  METHOD SetAudience( cAudience )           INLINE ::aPayload[ 'aud' ] := cAudience
  METHOD GetAudience()                      INLINE ::aPayload[ 'aud' ] 
  METHOD SetExpration( nExpiration )        INLINE ::aPayload[ 'exp' ] := nExpiration
  METHOD GetExpration()                     INLINE ::aPayload[ 'exp' ]
  METHOD SetNotBefore( nNotBefore )         INLINE ::aPayload[ 'nbf' ] := nNotBefore
  METHOD GetNotBefore()                     INLINE ::aPayload[ 'nbf' ]
  METHOD SetIssuedAt( nIssuedAt )           INLINE ::aPayload[ 'iat' ] := nIssuedAt
  METHOD GetIssuedAt()                      INLINE ::aPayload[ 'iat' ] 
  METHOD SetJWTId( cJWTId )                 INLINE ::aPayload[ 'jti' ] := cJWTId
  METHOD GetJWTId()                         INLINE ::aPayload[ 'jti' ] 

  // Payload methods
  METHOD SetPayloadData( cKey, uValue )     INLINE ::aPayload[ cKey ] := uValue
  METHOD GetPayloadData( cKey )             INLINE ::aPayload[ cKey ]

  // Secret
  METHOD SetSecret( cSecret )               INLINE ::cSecret := cSecret
  METHOD GetSecret()                        INLINE ::cSecret 

  // Error
  METHOD GetError()                         INLINE ::cError

  // Cleanup: aHeader, aPayload, cError, cSecret
  METHOD Reset()

  // Encode a JWT and return it
  METHOD Encode()

  // Decode a JWT
  METHOD Decode( cJWT, cSecret )

  // Getter internal data with internal exposion
  METHOD GetPayload()                       INLINE hb_hClone(::aPayload)
  METHOD GetHeader()                        INLINE hb_hClone(::aHeader)

  // Helper method for expiration setting
  METHOD GetSeconds() 

ENDCLASS

METHOD New() CLASS JWT
  ::Reset()
RETU SELF

// Optional
METHOD SetType( cType ) CLASS JWT
  LOCAL bRet := .F.

  IF cType=="JWT"
      ::aHeader[ 'typ' ] := cType
  ELSE
      bRet := .F.
      ::cError := "Invalid type [" +cType +"]"
  ENDIF

RETU bRet

// Mandatory
METHOD SetAlgorithm( cAlgorithm ) CLASS JWT
  LOCAL bRet := .F.

  IF cAlgorithm=="HS256" .OR. cAlgorithm=="HS384" .OR. cAlgorithm=="HS512"
      ::aHeader[ 'alg' ] := cAlgorithm
  ELSE
      bRet := .F.
      ::cError := "Invalid algorithm [" +cAlgorithm +"]"
  ENDIF

RETU bRet

METHOD Reset() CLASS JWT

  ::aHeader   := {=>}
  ::aPayload := {=>}
  ::cError  := ''
  ::cSecret  := ''

RETU NIL


METHOD Encode() CLASS JWT

  LOCAL cHeader
  LOCAL cPayload
  LOCAL cSignature 

  //  Encode header
  cHeader     := ::Base64UrlEncode( hb_jsonEncode( ::aHeader ) )

  // Encode payload
  cPayload    := ::Base64UrlEncode( hb_jsonEncode( ::aPayload ) )

  //  Make signature
  cSignature := ::GetSignature( cHeader, cPayload, ::cSecret, ::aHeader[ 'alg' ] )

//  Return JWT
RETU cHeader + '.' + cPayload + '.' + cSignature

METHOD Base64UrlEncode( cData ) CLASS JWT
RETU hb_StrReplace( hb_base64Encode( cData ), "+/=", { "-", "_", "" } )

METHOD Base64UrlDecode( cData ) CLASS JWT
RETU hb_base64Decode( hb_StrReplace( cData, "-_", "+/" ) )

METHOD ByteToString( cData ) CLASS JWT
   LOCAL cRet := SPACE(LEN(cData)/2)
   LOCAL nLen := LEN( cData )
   LOCAL nX, nNum

   cData := UPPER(cData)    
   FOR nX := 1 TO nLen STEP 2
      nNum := ( AT( SubStr( cData, nX  , 1 ), "0123456789ABCDEF" ) - 1 ) * 16
      nNum += AT( SubStr( cData, nX+1, 1 ), "0123456789ABCDEF" ) - 1 
      HB_BPOKE( @cRet, (nX+1)/2, nNum )
   NEXT

RETU cRet

METHOD GetSignature( cHeader, cPayload, cSecret, cAlgorithm ) CLASS JWT
  LOCAL cSignature := ""

  DO CASE
     CASE cAlgorithm=="HS256"
         cSignature := ::Base64UrlEncode( ::ByteToString( HB_HMAC_SHA256( cHeader + '.' + cPayload, cSecret ) ) )
     CASE cAlgorithm=="HS384"
         cSignature := ::Base64UrlEncode( ::ByteToString( HB_HMAC_SHA384( cHeader + '.' + cPayload, cSecret ) ) )
     CASE cAlgorithm=="HS512"
         cSignature := ::Base64UrlEncode( ::ByteToString( HB_HMAC_SHA512( cHeader + '.' + cPayload, cSecret ) ) )
     OTHERWISE
         ::cError := "INVALID ALGORITHM"
  ENDCASE
RETU cSignature

METHOD Decode( cJWT, cSecret ) CLASS JWT

  LOCAL aJWT
  LOCAL cSignature, cNewSignature

  // Reset Object
  ::Reset()

  //  Split JWT
  aJWT := HB_ATokens( cJWT, '.' )
  IF LEN(aJWT) <> 3
      ::cError := "Invalid JWT"
      RETU .F.
  ENDIF

  // Explode header
  ::aHeader   := hb_jsonDecode( ::Base64UrlDecode( aJWT[1] ))

  // Exploce payload
  ::aPayload   := hb_jsonDecode( ::Base64UrlDecode( aJWT[2] ))

  // Get signature
  cSignature  := aJWT[3]

  ::SetSecret( cSecret )

  // Calculate new sicnature
  cNewSignature   := ::GetSignature( aJWT[1], aJWT[2], cSecret, ::aHeader[ 'alg' ] )
  IF ( cSignature != cNewSignature )
    ::cError := "Invalid signature"
    RETU .F.
  ENDIF

  // Check expiration
  IF hb_HHasKey(::aPayLoad,'exp')
     IF ::aPayLoad[ 'exp' ] < ::GetSeconds()
       ::cError := "Token expired"
       RETU .F.
     ENDIF
  ENDIF

RETU .T.

METHOD GetSeconds() CLASS JWT

  LOCAL posixday := date() - STOD("19700101")
  LOCAL cTime := time()
  LOCAL posixsec := posixday * 24 * 60 * 60

RETU posixsec + (int(val(substr(cTime,1,2))) * 3600) + (int(val(substr(cTime,4.2))) * 60) + ( int(val(substr(cTime,7,2))) )

