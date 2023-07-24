@echo off
@set path=t:\harbour\bin
@set include=t:\harbour\include

harbour test\jwttest.prg /n /w3 /gh /oout\jwttest
if %errorlevel% neq 0 pause

harbour test\jwtcreate.prg /n /w3 /gh /oout\jwtcreate
if %errorlevel% neq 0 pause

cd out

hbrun jwttest.hrb>jwttest.log
type jwttest.log

hbrun jwtcreate.hrb>jwtcreate.log
type jwtcreate.log

cd ..

