import requests
import random
import string
import argparse
import hashlib
import datetime


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
}

def xor(s, key):
    res = ""
    for i in range(len(s)):
        res += chr(s[i] ^ ord(key[i % len(key)]))
    return res


def get_key(c2, url, tls, botid, proxy):
    key = ""
    print("Getting xor key")
    try:
        init = requests.post("http%s://%s%s?%s" % ("s" if tls else "", c2, url, botid), proxies=proxy, headers=headers)
    except Exception as e:
        print("Connection error with %s" % (c2))
        print(e)
        exit()

    if init.status_code == 200:
        key = init.text
    else:
        print(init.text)
        print("ERROR CANNOT GET KEY")
        exit()

    return key

def get_injects(c2, url, tls, botid, key, proxy):
    print("Getting config for %s" % (c2))
    config = requests.post("http%s://%s%s?%s" % ( "s" if tls else "", c2, url, botid), data = xor(bytearray("injects|", "ascii"), key), proxies=proxy, headers=headers)
    return xor(config.content, key).replace(botid, "<BOTID>")

def get_32bits_binary(c2, url, tls, botid, key, proxy):
    print("Getting 32 bits binary for %s" % (c2))
    config = requests.post("http%s://%s%s?%s" % ("s" if tls else "", c2, url, botid), data = xor(bytearray("bin|int32", "ascii"), key), proxies=proxy, headers=headers)
    return xor(config.content, key)

def get_64bits_binary(c2, url, tls, botid, key, proxy):
    print("Getting 64 bits binary for %s" % (c2))
    config = requests.post("http%s://%s%s?%s" % (  "s" if tls else "", c2, url, botid), data = xor(bytearray("bin|", "ascii"), key), proxies=proxy, headers=headers)
    return xor(config.content, key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Grab config and binaries from Tinynuke C2')
    parser.add_argument('c2', help="c2's hostname")
    parser.add_argument('--url',nargs='?', default="/admin/client.php", help="c2's entry point url (default /admin/client.php)")
    parser.add_argument('--tls', action="store_true", help="switch to enable https on c2")
    parser.add_argument('--ref-config',nargs='?', help="config used as reference to spot differences")
    parser.add_argument('--ref-32-binary',nargs='?', help="32 bit binary used as reference to spot differences")
    parser.add_argument('--ref-64-binary',nargs='?', help="64 bit binary used as reference to spot differences")
    parser.add_argument('--tor', action="store_true", help="switch to enable tor (must listen on localhost:9050)")
    args = parser.parse_args()
    botid = ''.join(random.choice("ABCDEF" + string.digits) for _ in range(16))
    print(botid)
    c2 = args.c2
    url = args.url
    tls = args.tls
    if args.tor:
        proxy = dict(http="socks5h://localhost:9050", https="socks5h://localhost:9050")
    else:
        proxy = None
    key = get_key(c2, url, tls, botid, proxy)
    injects = get_injects(c2, url, tls, botid, key, proxy)
    bin32 = get_32bits_binary(c2, url, tls, botid, key, proxy)
    bin64 = get_64bits_binary(c2, url, tls, botid, key, proxy)
    now = datetime.datetime.now()
    date = now.strftime("%Y-%m-%d %H:%M")
    config_filename = "%s_tinynuke_config_%s.json" % (c2, date)
    bin_32_filename = "%s_tinynuke_32bin_%s.bin" % (c2, date)
    bin_64_filename = "%s_tinynuke_64bin_%s.bin" % (c2, date)


    if args.ref_config:
        with open(args.ref_config, "r") as f:
            orig_hash = hashlib.sha1(f.read()).hexdigest()
            new_hash = hashlib.sha1(injects).hexdigest()
            if orig_hash == new_hash:
                print("No difference in config")
            else:
                print("New config")
                with open(config_filename, "w") as o:
                    o.write(injects)
    else:
        with open(config_filename, "w") as o:
            o.write(injects)


    if args.ref_32_binary:
        with open(args.ref_32_binary, "r") as f:
            orig_hash = hashlib.sha1(f.read()).hexdigest()
            new_hash = hashlib.sha1(bin32).hexdigest()
            if orig_hash == new_hash:
                print("No difference in 32 bit binary")
            else:
                print("New 32 bit binary")
                with open(bin_32_filename, "w") as o:
                    o.write(bin32)
    else:
        with open(bin_32_filename, "w") as o:
            o.write(bin32)

    if args.ref_64_binary:
        with open(args.ref_64_binary, "r") as f:
            orig_hash = hashlib.sha1(f.read()).hexdigest()
            new_hash = hashlib.sha1(bin64).hexdigest()
            if orig_hash == new_hash:
                print("No difference in 64 bit binary")
            else:
                print("New 64 bit binary")
                with open(bin_64_filename, "w") as o:
                    o.write(bin64)
    else:
        with open(bin_64_filename, "w") as o:
            o.write(bin64)
