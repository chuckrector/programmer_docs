@echo off

setlocal

if not exist "build" mkdir build
pushd build

start /b cl /nologo /GS- /Gs9999999 /Od /FC /Z7 ..\msdn_entry_to_text.c /link /stack:0x100000,0x100000
start /b cl /nologo /GS- /Gs9999999 /Od /FC /Z7 ..\load_pe.c /link /stack:0x100000,0x100000
