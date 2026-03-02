@echo off
javac -d bin -sourcepath src src\dk\cipherforge\CipherForge.java
jar cfm jar\CipherForge.jar Manifest.txt -C bin dk/cipherforge 
REM jdeps -s .\jar\CipherForge.jar
REM jlink --add-modules java.base --output cipherforge-runtime --launcher cipherforge-cli=dk.cipherforge.CipherForge
