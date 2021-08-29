@echo off

setlocal

if not exist "build" mkdir build
pushd build

cl /nologo /GS- /Gs9999999 /Od /FC /Z7 ..\msdn_entry_to_text.cpp /link /stack:0x100000,0x100000
