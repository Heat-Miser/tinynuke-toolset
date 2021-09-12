# Tinynuke injects and DLL grabber

That script has been developped to help an analyst to grab injects and DLLs from a Tinynuke c2.
The scripts use the malware protocol to discuss with the c2 and recover timestamped injects and 32 and 64 bits DLL.

To do that the analyst must identify the C2 and the PHP script endpoint used by the malware.

The protocol used by Tinynuke is quite simple.

1. You need to get a xor key, for that just do a GET request on the c2 PHP endpoint, a SHA-1 sum will be served in the output, this is the xor key.
2. Then that key will be used to discuss with the endpoint:
    * sending a POST request with "injects|" xored with the key in data will serve you the injects xored with the same key
    * sending a POST request with "bin|int32" xored with the key in data will serve you the 32 bits DLL xored with the same key
    * sending a POST request with "bin|" xored with the key in data will serve you the 64 bits DLL xored with the same key

The script does all that for you in one shot and store the collected files in the current directory with the following name: 
* `<c2 hostname>_tinynuke_config_<datetime>.json`
* `<c2 hostname>_tinynuke_32bin_<datetime>.bin`
* `<c2 hostname>_tinynuke_64bin_<datetime>.bin`

Usage examples:

* if your c2 is not a .onion, there is no certificate and the PHP endpoint is let by default (/admin/client.php): 

```
$> python3 tinynuke_config_grabber.py myhostname.c2.cm
```

* if your c2 is not a .onion, but served over TLS and the PHP endpoint has been modified: 

```
$> python3 tinynuke_config_grabber.py --tls --url "/myendpoint/client.php" myhostname.c2.cm
```

* if your c2 is served over TOR, and the PHP endpoint has been modified (you need to have a TOR client listening on the local TCP port 9050): 

```
$> python3 tinynuke_config_grabber.py --tor --url "/myendpoint/client.php" myhostname.onion
```

* if you wanna check if the 32 bit DLL served is different from the previous one you grabbed

```
$> python3 tinynuke_config_grabber.py --tor --url "/myendpoint/client.php" --ref-32-binary myhostname_ref_32bits.bin myhostname.onion
```

Similar options are available for 64 bits binaries and JSON injects file, just check the usage for more details.