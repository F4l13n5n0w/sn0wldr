# C2Loader

## This is used to generate a AV bypassed C2 loader from shellcode.

### Currently supporting the following C2 plateform (It is now should be able to support any C2 if shellcode is provided):

* Meterpreter
* Covenent
* Sliver
* Cobalt Strike


### Feature

* Process Hollowing
* Behaviour detection bypass
* Random AES encryption
* Rewrite to use D/Invoke direct syscalls (up to test day, most common AVs can be bypassed: Windows defender, CS Falcon, Carbon Black, Red Canary, Cylance and McAfee)

### Guide

* miniloader_template is ideal for small shellcode, such as meterpreter shellcode generated by msfvenom, it has better AV byapss since it is not using a well known WIN32 API: ZwMapViewOfSection

### To Do

* Add bananameowloader for even better AV bypass
* Add InlineExecute-Assembly BoF support for Sliver