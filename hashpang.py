#!/bin/python3
# coding=utf-8
import hashlib
import argparse
import sys
import pyfiglet

print(pyfiglet.figlet_format('hashpang'))
parser = argparse.ArgumentParser(description='根据加密明文字典比对hash', usage='python3 hashpang.py -H hash', argument_default='')
parser.add_argument('-H', '--hash', metavar='', help='需要撞库的哈希', type=str)
parser.add_argument('-D', '--dic', metavar='', help='指定字典(默认内置字典dic.txt)', default='dic.txt')
argv = parser.parse_args()
m = argv.hash
f = argv.dic
if len(m) == 32 or len(m) == 40 or len(m) == 56 or len(m) == 64 or len(m) == 96 or len(m) == 128:
    with open(f, 'r') as f:
        for i in f:
            md5 = hashlib.md5(i.strip().encode(encoding='utf-8')).hexdigest()
            sha1 = hashlib.sha1(i.strip().encode(encoding='utf-8')).hexdigest()
            sha224 = hashlib.sha224(i.strip().encode(encoding='utf-8')).hexdigest()
            sha256 = hashlib.sha256(i.strip().encode(encoding='utf-8')).hexdigest()
            sha384 = hashlib.sha384(i.strip().encode(encoding='utf-8')).hexdigest()
            sha512 = hashlib.sha512(i.strip().encode(encoding='utf-8')).hexdigest()

            if len(m) == 32:  # md5
                if m == md5:  # md5(%pass)
                    print('[+]md5(%pass):' + i.strip())
                    break
                else:
                    md5 = hashlib.md5(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha1 = hashlib.md5(sha1.strip().encode(encoding='utf-8')).hexdigest()
                    sha224 = hashlib.md5(sha224.strip().encode(encoding='utf-8')).hexdigest()
                    sha256 = hashlib.md5(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    sha384 = hashlib.md5(sha384.strip().encode(encoding='utf-8')).hexdigest()
                    sha512 = hashlib.md5(sha512.strip().encode(encoding='utf-8')).hexdigest()
                    if m == md5:  # md5(md5(%pass))
                        print('[+]md5(md5(%pass)):' + i.strip())
                        break
                    elif m == sha1:  # md5(sha1(%pass))
                        print('[+]md5(sha1(%pass)):' + i.strip())
                        break
                    elif m == sha224:
                        print('[+]md5(sha224(%pass)):' + i.strip())
                        break
                    elif m == sha256:
                        print('[+]md5(sha256(%pass)):' + i.strip())
                        break
                    elif m == sha384:
                        print('[+]md5(sha384(%pass)):' + i.strip())
                        break
                    elif m == sha512:
                        print('[+]md5(sha512(%pass)):' + i.strip())
                        break

            if len(m) == 40:  # sha1
                if m == sha1:  # sha1(%pass)
                    print('[+]sha1(%pass):' + i.strip())
                    break
                else:
                    md5 = hashlib.sha1(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha1 = hashlib.sha1(sha1.strip().encode(encoding='utf-8')).hexdigest()
                    sha224 = hashlib.sha1(sha224.strip().encode(encoding='utf-8')).hexdigest()
                    sha256 = hashlib.sha1(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    sha384 = hashlib.sha1(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    sha512 = hashlib.sha1(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    if m == sha1:  # sha1(sha1(%pass))
                        print('[+]sha1(sha1(%pass)):' + i.strip())
                        break
                    elif m == md5:  # sha1(md5(%pass))
                        print('[+]sha1(md5(%pass)):' + i.strip())
                        break
                    elif m == sha224:
                        print('[+]sha1(sha224(%pass)):' + i.strip())
                        break
                    elif m == sha256:
                        print('[+]sha1(sha256(%pass)):' + i.strip())
                        break
                    elif m == sha384:
                        print('[+]sha1(sha384(%pass)):' + i.strip())
                        break
                    elif m == sha512:
                        print('[+]sha1(sha512(%pass)):' + i.strip())
                        break

            if len(m) == 56:  # sha224
                if m == sha224:
                    print('[+]sha224(%pass):' + i.strip())
                    break
                else:
                    md5 = hashlib.sha224(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha1 = hashlib.sha224(sha1.strip().encode(encoding='utf-8')).hexdigest()
                    sha224 = hashlib.sha224(sha224.strip().encode(encoding='utf-8')).hexdigest()
                    sha256 = hashlib.sha224(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    sha384 = hashlib.sha224(sha384.strip().encode(encoding='utf-8')).hexdigest()
                    sha512 = hashlib.sha224(sha512.strip().encode(encoding='utf-8')).hexdigest()
                    if m == sha1:  # sha224(sha1(%pass))
                        print('[+]sha224(sha1(%pass)):' + i.strip())
                        break
                    elif m == md5:  # sha224(md5(%pass))
                        print('[+]sha224(md5(%pass)):' + i.strip())
                        break
                    elif m == sha224:
                        print('[+]sha224(sha224(%pass)):' + i.strip())
                        break
                    elif m == sha256:
                        print('[+]sha224(sha256(%pass)):' + i.strip())
                        break
                    elif m == sha384:
                        print('[+]sha224(sha384(%pass)):' + i.strip())
                        break
                    elif m == sha512:
                        print('[+]sha224(sha512(%pass)):' + i.strip())
                        break

            if len(m) == 64:  # sha256
                if m == sha256:
                    print('[+]sha256(%pass):' + i.strip())
                    break
                else:
                    md5 = hashlib.sha256(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha1 = hashlib.sha256(sha1.strip().encode(encoding='utf-8')).hexdigest()
                    sha224 = hashlib.sha256(sha224.strip().encode(encoding='utf-8')).hexdigest()
                    sha256 = hashlib.sha256(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    sha384 = hashlib.sha256(sha384.strip().encode(encoding='utf-8')).hexdigest()
                    sha512 = hashlib.sha256(sha512.strip().encode(encoding='utf-8')).hexdigest()
                    if m == sha1:
                        print('[+]sha256(sha1(%pass)):' + i.strip())
                        break
                    elif m == md5:
                        print('[+]sha256(md5(%pass)):' + i.strip())
                        break
                    elif m == sha224:
                        print('[+]sha256(sha224(%pass)):' + i.strip())
                        break
                    elif m == sha256:
                        print('[+]sha256(sha256(%pass)):' + i.strip())
                        break
                    elif m == sha384:
                        print('[+]sha256(sha384(%pass)):' + i.strip())
                        break
                    elif m == sha512:
                        print('[+]sha256(sha512(%pass)):' + i.strip())
                        break

            if len(m) == 96:  # sha384
                if m == sha384:
                    print('[+]sha384(%pass):' + i.strip())
                    break
                else:
                    md5 = hashlib.sha384(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha1 = hashlib.sha384(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha224 = hashlib.sha384(sha224.strip().encode(encoding='utf-8')).hexdigest()
                    sha256 = hashlib.sha384(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    sha384 = hashlib.sha384(sha384.strip().encode(encoding='utf-8')).hexdigest()
                    sha512 = hashlib.sha384(sha512.strip().encode(encoding='utf-8')).hexdigest()
                    if m == sha1:
                        print('[+]sha384(sha1(%pass)):' + i.strip())
                        break
                    elif m == md5:
                        print('[+]sha384(md5(%pass)):' + i.strip())
                        break
                    elif m == sha224:
                        print('[+]sha384(sha224(%pass)):' + i.strip())
                        break
                    elif m == sha256:
                        print('[+]sha384(sha256(%pass)):' + i.strip())
                        break
                    elif m == sha384:
                        print('[+]sha384(sha384(%pass)):' + i.strip())
                        break
                    elif m == sha512:
                        print('[+]sha384(sha512(%pass)):' + i.strip())
                        break

            if len(m) == 128:  # sha512
                if m == sha512:
                    print('[+]sha512(%pass):' + i.strip())
                    break
                else:
                    md5 = hashlib.sha512(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha1 = hashlib.sha512(md5.strip().encode(encoding='utf-8')).hexdigest()
                    sha224 = hashlib.sha512(sha224.strip().encode(encoding='utf-8')).hexdigest()
                    sha256 = hashlib.sha512(sha256.strip().encode(encoding='utf-8')).hexdigest()
                    sha384 = hashlib.sha512(sha384.strip().encode(encoding='utf-8')).hexdigest()
                    sha512 = hashlib.sha512(sha512.strip().encode(encoding='utf-8')).hexdigest()
                    if m == sha1:
                        print('[+]sha512(sha1(%pass)):' + i.strip())
                        break
                    elif m == md5:
                        print('[+]sha512(md5(%pass)):' + i.strip())
                        break
                    elif m == sha224:
                        print('[+]sha512(sha224(%pass)):' + i.strip())
                        break
                    elif m == sha256:
                        print('[+]sha512(sha256(%pass)):' + i.strip())
                        break
                    elif m == sha384:
                        print('[+]sha512(sha384(%pass)):' + i.strip())
                        break
                    elif m == sha512:
                        print('[+]sha512(sha512(%pass)):' + i.strip())
                        break
        else:
            sys.exit('[-]字典内密码不包含此hash！')
