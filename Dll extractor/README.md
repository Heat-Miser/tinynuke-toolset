# DLL Extractor

I developed that script quickly to extract the main DLL from a loading DLL in the samples I was analyzing most of the time.

The threat actor I chased was using Innosetup to package the malware with all the dependencies. Then he used an old version of Firefox [vulnerable to a bug](https://bugzilla.mozilla.org/show_bug.cgi?id=1314108) allowing him to load any dll he wanted.

So if you take [that sample](https://www.virustotal.com/gui/file/d32a4447bbd41a5d4fb6ff5a075c55bc2becb9f949ffb7d731e1718ac1325dd4) and [innoextract](https://constexpr.org/innoextract/) it you'll get the following content:

```
$>ls -l
total 22856
drwxrwxr-x 2 hmiser hmiser    4096 août   4 11:55 ./
drwxrwxr-x 3 hmiser hmiser    4096 août   4 11:55 ../
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-core-console-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   17600 sept. 18  2018 api-ms-win-core-datetime-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   17600 sept. 18  2018 api-ms-win-core-debug-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18104 sept. 18  2018 api-ms-win-core-errorhandling-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   21696 sept. 18  2018 api-ms-win-core-file-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-file-l1-2-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-file-l2-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-handle-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-heap-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18104 sept. 18  2018 api-ms-win-core-interlocked-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-core-libraryloader-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   20672 sept. 18  2018 api-ms-win-core-localization-l1-2-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-core-memory-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-namedpipe-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   19136 sept. 18  2018 api-ms-win-core-processenvironment-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   20160 sept. 18  2018 api-ms-win-core-processthreads-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-core-processthreads-l1-1-1.dll
-rw-rw-r-- 1 hmiser hmiser   17600 sept. 18  2018 api-ms-win-core-profile-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   17600 sept. 18  2018 api-ms-win-core-rtlsupport-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-string-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   20160 sept. 18  2018 api-ms-win-core-synch-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-core-synch-l1-2-0.dll
-rw-rw-r-- 1 hmiser hmiser   19136 sept. 18  2018 api-ms-win-core-sysinfo-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-timezone-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18112 sept. 18  2018 api-ms-win-core-util-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   19136 sept. 18  2018 api-ms-win-crt-conio-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   22208 sept. 18  2018 api-ms-win-crt-convert-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-crt-environment-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   20160 sept. 18  2018 api-ms-win-crt-filesystem-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-crt-heap-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-crt-locale-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   28864 sept. 18  2018 api-ms-win-crt-math-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   25792 sept. 18  2018 api-ms-win-crt-multibyte-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   72896 sept. 18  2018 api-ms-win-crt-private-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   19136 sept. 18  2018 api-ms-win-crt-process-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   22720 sept. 18  2018 api-ms-win-crt-runtime-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   24256 sept. 18  2018 api-ms-win-crt-stdio-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   24256 sept. 18  2018 api-ms-win-crt-string-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   20672 sept. 18  2018 api-ms-win-crt-time-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser   18624 sept. 18  2018 api-ms-win-crt-utility-l1-1-0.dll
-rw-rw-r-- 1 hmiser hmiser  171520 avril  5 03:56 data.dll
-rw-rw-r-- 1 hmiser hmiser      10 août  13  2020 dependentlibs.list
-rw-rw-r-- 1 hmiser hmiser  531408 sept. 18  2018 firefox.exe
-rw-rw-r-- 1 hmiser hmiser 3305439 mai   15  2020 libcrypto-1_1.dll
-rw-rw-r-- 1 hmiser hmiser 3204768 sept. 18  2018 libeay32.dll
-rw-rw-r-- 1 hmiser hmiser  717225 sept. 18  2018 libevent-2-0-5.dll
-rw-rw-r-- 1 hmiser hmiser  873957 mai   15  2020 libevent-2-1-7.dll
-rw-rw-r-- 1 hmiser hmiser  418255 sept. 18  2018 libevent_core-2-0-5.dll
-rw-rw-r-- 1 hmiser hmiser  591288 mai   15  2020 libevent_core-2-1-7.dll
-rw-rw-r-- 1 hmiser hmiser  408865 sept. 18  2018 libevent_extra-2-0-5.dll
-rw-rw-r-- 1 hmiser hmiser  574597 mai   15  2020 libevent_extra-2-1-7.dll
-rw-rw-r-- 1 hmiser hmiser 1109520 mai   15  2020 libgcc_s_sjlj-1.dll
-rw-rw-r-- 1 hmiser hmiser  829355 sept. 18  2018 libgmp-10.dll
-rw-rw-r-- 1 hmiser hmiser  951633 mai   15  2020 libssl-1_1.dll
-rw-rw-r-- 1 hmiser hmiser  268509 mai   15  2020 libssp-0.dll
-rw-rw-r-- 1 hmiser hmiser  535293 mai   15  2020 libwinpthread-1.dll
-rw-rw-r-- 1 hmiser hmiser  133072 sept. 18  2018 mozglue.dll
-rw-rw-r-- 1 hmiser hmiser  535008 sept. 18  2018 msvcp110.dll
-rw-rw-r-- 1 hmiser hmiser  440120 sept. 18  2018 msvcp140.dll
-rw-rw-r-- 1 hmiser hmiser  875472 sept. 18  2018 msvcr110.dll
-rw-rw-r-- 1 hmiser hmiser  713149 sept. 18  2018 ssleay32.dll
-rw-rw-r-- 1 hmiser hmiser 4135936 mai   15  2020 tor.exe
-rw-rw-r-- 1 hmiser hmiser  917184 sept. 18  2018 ucrtbase.dll
-rw-rw-r-- 1 hmiser hmiser   83784 sept. 18  2018 vcruntime140.dll
-rw-rw-r-- 1 hmiser hmiser  101888 mai   15  2020 zlib1.dll
```

in that gigantic list of dependencies, `dependendlibs.list` contains the name of the side loaded DLL:

```
$>cat dependentlibs.list 
data.dll
```
So our file of interest is here `data.dll` (https://www.virustotal.com/gui/file/0d0879052656ea64996d431b5de6d2c1cb4ce175797864e6c00b7f3e945e67d5)

If you have a look at the file using your favorite disassembler (let say Ghidra) you'll quickly find a suspicious long string with several references (a xor key) and a big blob.
They are the main elements you need to spot to extract the final DLL using that script.

![xor key](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/weird_string_xor_key.png?raw=true)

![key and blob](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/key_and_blob.png?raw=true)

![blob](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/xored_blob.png?raw=true)

You just have to grab the bytes source offset for those elements to use the script, hovering the adress in Ghidra will display the required information in hex.

![key offset](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/key_offset.png?raw=true)

![blob offset](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/data_offset.png?raw=true)

The last required information is the blob size, and that information can be spotted easly by looking for a CMP instruction just around the place where the key and blob are used.

![blob size](https://raw.githubusercontent.com/heat-miser/tinynuke-toolset/main/screenshots/blob_size.png?raw=true)

And then we can finally execute our script with the collected data:

```
$>python3 dll_extractor.py
usage: dll_extractor.py [-h] file blob size key
dll_extractor.py: error: the following arguments are required: file, blob, size, key

$>python3 dll_extractor.py /mydir/data.dll 0xf890 0x17000 0xf888
Succesfully extracted to /mydir/extracted_from_data.dll
```