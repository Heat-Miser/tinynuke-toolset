# Miasm toolset

Those scripts were my first attempt to automate the c2 extraction from the DLLs.

They are based on [Miasm reverse engineering framework](https://github.com/cea-sec/miasm), a toolset written by CEA Sec, the cybersecurity team of the French Atomic Energy research center.

This framework permits us to instrument the code present in binaries. I leveraged that functionality to unxor the obfuscated strings.

## How it works ?

1. you need to find the unxor function, for that I use a yara signature
2. I disassemble the function using Capstone until I reach the "RET" instruction (the end of the function)
3. I set up a breakpoint at that address, and execute the binary in a sandbox
4. Every time the breakpoint is reached I know RAX registry points to the decoded string, I just need to print it

The scripts are configured to stop after having discovered the PHP endpont, so it'll only display the C2 and the endpoint.

## How to use ?

Miasm is pretty cool but a bit painful to install on several OS, so I provide a Dockerfile.

First, build the docker image by moving to the miasm directory and using the following command

```
$>docker build -t miasm/tinynuke .
```

Then start a container (don't forget to bind the directory containing your samples)

```
$>docker run -i -v `pwd`:/data -t miasm/tinynuke  bash .
```

In the shell you just have to launch the scripts on your binaries

```
$>cd /tinynuke
$>python miasm_tinynuke_dll_32.py -q /data/32.bin 
cannot find crypto, skipping
[WARNING]: Create dummy entry for 'user32.dll'
[WARNING]: Create dummy entry for 'kernel32.dll'
fizi4aqe7hpsts3r.onion
/hci/client.php
$>python miasm_tinynuke_dll_64.py -q /data/64.bin 
cannot find crypto, skipping
[WARNING]: Create dummy entry for 'kernel32.dll'
[WARNING]: Create dummy entry for 'user32.dll'
fizi4aqe7hpsts3r.onion
/hci/client.php
```
