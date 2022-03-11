@echo off
@set path=t:\harbour\bin
@set include=t:\harbour\include

harbour src\jwt.prg /n /w3 /es1 /gh /olib\jwt
if %errorlevel% neq 0 pause

harbour test\jwttest.prg /n /w3 /gh /oout\jwttest
if %errorlevel% neq 0 pause

cd out
hbrun jwttest.hrb>jwttest.log
type jwttest.log
cd ..

