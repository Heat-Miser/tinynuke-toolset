# tinynuke-toolset

You'll find in that repository a set of tools and scripts I developped to analyze Tinynuke samples.

* Dll extractor: script used to extract the main Tinynuke DLL from the loader
* ghidra: set of Ghidra scripts allowing researchers to decode strings and resolve libraries dynamic loading
* injects and DLL grabber: a python script which is able to talk to a Tinynuke c2 to grab web injects and DLLs
* miasm: old CEA Sec miasm scripts used to decode dand grab c2 config from Tinynuke DLL sent by the c2

You'll find dedicated README's in the different directories with how to examples

These tools have been tested on the [following sample](https://www.virustotal.com/gui/file/d32a4447bbd41a5d4fb6ff5a075c55bc2becb9f949ffb7d731e1718ac1325dd4) (you can unpack it using [InnoExtract](https://constexpr.org/innoextract/))