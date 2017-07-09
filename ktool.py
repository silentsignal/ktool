#!/usr/bin/env python

from __future__ import print_function
from argparse import ArgumentParser
from sys import stderr, stdin
from os import path
import sqlite3
import re

def number_to_str(value):
    h = hex(value)[2:].rstrip('L')
    if len(h) % 2:
        h = '0' + h
    return h.decode('hex')

def str_to_number(value):
    return int(str(value).encode('hex'), 16)

def main():
    parser = ArgumentParser(
        description='Swiss Army Knife for keys and certificates')
    parser.add_argument('--import', dest='do_import', action='store_true')
    parser.add_argument('--export', dest='do_export', action='store_true')
    parser.add_argument('--search', dest='do_search', action='store_true')
    parser.add_argument('--list', dest='do_list', action='store_true')
    parser.add_argument('--format', dest='format')
    parser.add_argument('--comment', dest='comment')
    args = parser.parse_args()
    db = sqlite3.connect(path.expanduser('~/.config/ktool.sqlite3'))
    db.execute('CREATE TABLE IF NOT EXISTS rsa_keys (e, n, comment, PRIMARY KEY (e, n))')
    if args.format:
        args.format = args.format.lower()
    if args.format == 'rb64':
        e = '\x01\x00\x01' # XXX
        n = stdin.read().decode('base64')
    elif args.format == 'rhex':
        e = '\x01\x00\x01' # XXX
        n = re.sub('[^0-9a-f]+', '', stdin.read(), flags=re.I).decode('hex')
    elif args.format in ('der', 'pem'):
        from Crypto.PublicKey import RSA
        k = RSA.importKey(stdin.read())
        n = number_to_str(k.n)
        e = number_to_str(k.e)
    else:
        n = ''
    n = n.lstrip('\0')
    if args.do_import:
        try:
            db.execute('INSERT INTO rsa_keys (e, n, comment) VALUES (?, ?, ?)',
                    (sqlite3.Binary(e), sqlite3.Binary(n), args.comment))
            db.commit()
        except sqlite3.IntegrityError:
            row = db.execute('SELECT comment FROM rsa_keys WHERE n = ?', (sqlite3.Binary(n),)).fetchone()
            if row:
                print('Key already in database with comment: ' + row[0], file=stderr)
                raise SystemExit(1)
            else:
                raise
    elif args.do_export:
        row = db.execute('SELECT e, n FROM rsa_keys WHERE comment = ?', (args.comment,)).fetchone()
        if row:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            e, n = (str_to_number(p) for p in row)
            pk = RSAPublicNumbers(e, n).public_key(default_backend())
            print(pk.public_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        else:
            print('No key with matching comment found', file=stderr)
            raise SystemExit(1)
    elif args.do_search:
        row = db.execute('SELECT comment FROM rsa_keys WHERE n = ?', (sqlite3.Binary(n),)).fetchone()
        if row:
            print('Comment: ' + row[0])
        else:
            print('No modulus matches in database', file=stderr)
            raise SystemExit(1)

    elif args.do_list:
        c = db.execute('SELECT e, n, comment FROM rsa_keys ORDER BY e, n')
        print('{0:>8} {1:32} {2:>5} {3}'.format('e', 'n (first 16 octets from MSB)', 'nbits', 'comment'))
        print('=' * 80)
        for e, n, comment in c:
            print('{0:>8} {1:32} {2:>5} {3}'.format(e[:4].encode('hex'),
                n[:16].encode('hex'), len(n) * 8, comment))


if __name__ == '__main__':
    main()
