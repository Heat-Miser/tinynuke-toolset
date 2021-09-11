import argparse
import os

def extract_blob_and_key(file, blob, size, key):
    binary_blob = None
    extracted_key = b""
    with open(file, "rb") as f:
        f.seek(blob, 0)
        binary_blob = f.read(size)
        f.seek(key, 0)
        c = f.read(1)
        while c != b"\0":
            extracted_key += c
            c = f.read(1)

    return (binary_blob, extracted_key)


def unxor(encoded_key, encoded_string, size):
    decoded_string = b''
    i = 0
    for i in range(size):
        decoded_string = decoded_string + bytes([encoded_string[i] ^ encoded_key[i % len(encoded_key)]])
    
    return decoded_string


def __auto_int(x):
    return int(x, 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract DLL from DLL found in the Innosetup package')
    parser.add_argument('file', help="original DLL")
    parser.add_argument('blob', type=__auto_int, help="Blob offset in the binary")
    parser.add_argument('size', type=__auto_int, help="Blob size")
    parser.add_argument('key', type=__auto_int, help="Key offset in the binary")
    
    args = parser.parse_args()
    res = extract_blob_and_key(args.file, args.blob, args.size, args.key)
    extracted_dll = unxor(res[1], res[0], args.size)
    output_filename = f"{os.path.dirname(args.file)}{os.path.sep}extracted_from_{os.path.basename(args.file)}"
    with open(output_filename, 'wb') as o:
        o.write(extracted_dll)

    print(f"Succesfully extracted to {output_filename}" )