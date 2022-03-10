@echo off
@set path=t:\harbour\bin
@set include=t:\harbour\include

harbour src\jwt.prg /n /w /gh
if %errorlevel% neq 0 pause

harbour test\jwttest.prg /n /w /gh
if %errorlevel% neq 0 pause

hbrun jwttest.hrb>jwt.log

