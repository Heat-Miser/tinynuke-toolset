# Ghidra scripts

you can load those scripts in your Ghidra by adding the corresponding directory in the loaded dirs of the Script managers.

![dirs ghidra](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/scripts_dirs_ghidra.png?raw=true)

You'll then find a new category in the script manager called "Tinynuke" with those 3 scripts in it.

## TinynukeExtractDll.py

This script is a Ghidra version of the Dll Extractor written in pure Python and available [here](https://github.com/Heat-Miser/tinynuke-toolset/tree/main/Dll%20extractor).

Collect the required informations and execute the script. It will then prompt them to you and extract the dll in the same directory and output the path on the console.

## TinynukeUnxor.py

This script has been written to be run on a main Tinynuke DLL extracted from the C2 or from the loaded (see previous script or Dll Extractor).

Tinynuke has been developped with a simple mechanism to obfuscate strings. Every string can be prepended by a marker which will allow to replace them by a call to a xor function (see: [AutoEncrypt](https://github.com/rossja/TinyNuke/blob/master/AutoEncrypt/AutoEncrypt/Program.cs))

So most of the time, strings, including C2, are obbfuscated and not human readable making reverse engineering and configuration extraction a bit harder.

I wrote that Ghidra script to help an analyst working on Tinynuke DLL in Ghidra, it works by looking for references for the unxor function. It'll then try to recover the three parameters (xor key, xored string and data size) automatically and add the decoded string a repeatable comment at the address of the encoded string.

When you load the DLL in Ghidra, just have a look at the entry function, it should look like this:

![entry function](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/entry_function.png?raw=true)

Then jump into the very first function call and you'll enter in the "configuration loader". That function is used to unxor every string and load dynamically the different dependencies used by Tinynuke.

![config loader](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/conf_loader.png?raw=true)

We'll focus on the strings unxoring, for that you just have to note the function name used to unxor (you can rename it) and then launch the script.

A prompt will then ask you the unxor function name and every xored string will be decorated by a repeatable comment. All the decoded strings are also displayed in the console output.

![unxored strings](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/unxored_strings.png?raw=true)

The two first ones contain the C2 address and the PHP endpoint.

## TinynukeGetprocAddress.py

This script has been written to be run on a main Tinynuke DLL extracted from the C2 or from the loaded (see previous script or Dll Extractor).

By using the previous script, you'll quickly notice that most of the decoded strings are DLL and functions names. They're used to load functions dynamically using GetProcAddress.

It's another common obfuscation mechanism used in a lot of malware. The goal is to avoid having obvious imports which could help reversing the sample.

By scrolling in the code of Tinynuke DLL config loader function, you'll find easily a piece of code resolving the different imports dynamically.

![dynamic getprocaddress](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/dynamic_getproc.png?raw=true)

There is unique explicite getProcAddress call used to dynamically load getProcAddress (?????????????) then you'll find a lot of call to the getProcAdress handle with two parameters:
* a function name
* a library handle

This scripts takes advantage of that to rename the different pointers in the code used to store the different function handles. Execute the script and it will prompt you the name of the label used to store the dynamically loaded getProcAddress (you can rename it but in the screenshot DAT_100163b4), it'll then find automatically the different parameters and rename the different handles in the binary to help further analysis.

![dynamic getprocaddress](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/handles_resolved.png?raw=true)


## TinynukePackerDeobfuscation.py

This script has been developped to deal with the latest version of Tinynuke (which appeared circa 10th of November 2021). In those versions the intermediate packing mechanism has been obfuscated to make the unpacking a bit harder.

If you open [one of the latest payloads](https://www.virustotal.com/gui/file/8fce366f8b2dadd9dfff768490209d50a4f67dade7c5442c94ae012c92f17e03/detection) and open the embbeded `data.dll` you'll probably struggle to find the xor key to extract the level two DLL, that's because noise has been hadded in the threat function in charge of that part.

If you try to decompile it using Ghidra, the decompiler will probably rage quit facing the big amount of useless instructions added into that function.

That scripts has been developped to avoid overloading the decompiler. You just have to find the created thread entry in the DLL (just follow the DLL entry) and it will detect the useless instruction sections and patch the binary to jump them. Then it'll force the decompiler to reanalyze the function. As most of the useless code will never be executed due to the added unconditionnal jumps, the decompilation is way more quicker.

![create thread entry](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/ThreadAddress.png?raw=true)

The script is not perfect and noise remains, but it'll make the unpacking easier and faster with that added obfuscation. 

![deobfuscated unxor](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/rolling_xor_deobfuscated.png?raw=true)

One last thing, in the latest version the rolling xor used to unpack the level 2 dll is not using directly the xor key but a pointer to the key, don't fall in that easy trap, and don't forget to give the correct address to the unpacking script or you'll end with junk instead of a DLL.