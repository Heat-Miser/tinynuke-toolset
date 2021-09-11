#Script used to extract Tinynuke DLL from loader
#@author Hash Miser (@h_miser) <contact@heat-miser.net>
#@category Tinynuke Tools


def unxor(encoded_key, encoded_string, size):
	decoded_string = b""
	i = 0
	for i in range(0, size):
		decoded_string += chr(ord(encoded_string[i]) ^ ord(encoded_key[i % len(encoded_key)]))
	
	return decoded_string

def get_key(address):
    c = getByte(address)
    res = ""
    while c != 0:
        res += chr(c)
        address = address.add(1)
        c = getByte(address)

    return res

def get_data(address, size):
    counter = 0
    res = b""
    add = address
    while counter < size:
        res += chr(getByte(add) & 0xFF)
        counter += 1 
        add = address.add(counter)
    return res

def main():
    key_address = toAddr(askString("Key address", "Enter xor key address"))
    blob_address = toAddr(askString("Blob address", "Enter xored binary address"))
    blob_size = askInt("Blob size", "Enter binary blob size")

    key = get_key(key_address)
    data = get_data(blob_address, blob_size)
    results = unxor(key, data, blob_size)
    program_name = getProgramFile().toString() + "__extracted_dll"

    with open(program_name, "wb") as f:
        f.write(bytearray(results))

    if results[0] == "M" and results[1] == "Z":
        print("Binary successfully exported at %s" % (program_name))
        
if __name__ == "__main__":
    main()