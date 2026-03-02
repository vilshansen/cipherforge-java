#!/bin/bash

# Create directories if they don't exist
mkdir -p bin jar

# Compile Java files
javac -d bin -sourcepath src src/dk/cipherforge/CipherForge.java

# Create JAR file
jar cfm jar/CipherForge.jar Manifest.txt -C bin dk/cipherforge

# Create a minimal runtime with just java.base
#jlink --add-modules java.base --output cipherforge-runtime

# To run your program with this runtime, you need to include your JAR:
# ./cipherforge-runtime/bin/java -cp jar/CipherForge.jar dk.cipherforge.CipherForge
