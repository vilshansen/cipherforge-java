#!/bin/bash
rm -f test.bin*
dd if=/dev/urandom of=test.bin bs=1M count=100
sha256sum test.bin > test.bin.sha256
java -jar jar/CipherForge.jar -e test.bin
rm -f test.bin
java -jar jar/CipherForge.jar -d test.bin.cfo
sha256sum -c test.bin.sha256

FILE_SIZE=$(stat -c%s test.bin.cfo)
OFFSET=$((RANDOM % FILE_SIZE))
echo "Corrupting 1 byte at offset $OFFSET in test.bin.cfo..."
dd if=/dev/urandom of="test.bin.cfo" bs=1 seek=$OFFSET count=1 conv=notrunc status=none

echo "Attempting to decrypt corrupted file -- expect failure..."
rm -f test.bin
java -jar jar/CipherForge.jar -d test.bin.cfo
