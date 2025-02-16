#!/bin/env python3
from __future__ import print_function,division
import sys
if sys.version_info < (3, 0):
    range = xrange

import argparse
import hn_encryption as hn

def read_input(fname:str) -> str:
    if fname == '-':
        return sys.stdin.read()
    else:
        with open(fname) as f:
            return f.read()

# Modes
def decypher(args):
    cipher = read_input(args.infile)

    if args.brute:
        dec,plain = hn.decrypt_brute(cipher, args.layers, args.verbose, args.OS)
    else:
        dec,plain = hn.decrypt(cipher, args.password.encode('utf-8'), args.layers, args.verbose, args.OS)

    if args.outfile == '-':
        sys.stdout.write(plain.decode(encoding='utf-8', errors='replace'))
    else:
        outfile = args.outfile+dec.extension
        with open(outfile, 'wb') as f:
            f.write(plain)

def dechead(args):
    cipher = read_input(args.infile)
    hn.print_header(cipher, args.OS)

def encypher(args):
    plain = read_input(args.infile)

    i = args.infile.rfind('.')
    extension = args.infile[i:] if i != -1 else ''

    cipher = hn.encrypt(args.comment, args.signature, args.OS, extension,
                                  plain, args.password.encode('utf-8'))

    if args.outfile == '-':
        sys.stdout.write(cipher)
    else:
        outfile = args.outfile
        with open(outfile, 'w') as f:
            f.write(cipher)

# Input parsing
parser = argparse.ArgumentParser()

parser.description = """
Decodes the DEC_ENC format used in Hacknet.
"""

parser.add_argument('-v',
                    action="store_true", dest='verbose',
                    help="verbose mode")
parser.set_defaults(mode=lambda x:parser.print_usage())


subparsers = parser.add_subparsers(
        title='modes')
        #description='valid modes'

# Decypher
dec_parser = subparsers.add_parser('decypher', help='decryption mode')

dec_parser.add_argument('infile',
                        nargs='?', default='-',
                        help="input file")
dec_parser.add_argument('password',
                        nargs='?', default='',
                        help="password to use, defaults to no password")
dec_parser.add_argument('-o',
                        metavar='outfile', default='-', dest='outfile',
                        help="output file base name")
dec_parser.add_argument('--brute',
                        action="store_true",
                        help="brute force solve the file, with verbose also prints a valid password")
dec_parser.add_argument('--layers', '-n',
                        default=1, type=int, metavar='n',
                        help="layers of decryption")
dec_parser.add_argument('--OS', '-O',
                        default=sys.platform,
                        help="force a specific hashing algorithm, defaults to current OS (windows,linux)")

dec_parser.set_defaults(mode=decypher)

# Dechead
head_parser = subparsers.add_parser('dechead', help='header decryption mode')

head_parser.add_argument('infile',
                         nargs='?', default='-',
                         help="input file")
head_parser.add_argument('--OS', '-O',
                        default=sys.platform,
                        help="force a specific hashing algorithm, defaults to current OS (windows,linux)")

head_parser.set_defaults(mode=dechead)

# Encypher
enc_parser = subparsers.add_parser('encypher', help='encryption mode')

enc_parser.add_argument('infile',
                        nargs='?', default='-',
                        help="input file")
enc_parser.add_argument('password',
                        nargs='?', default='',
                        help="password to use, defaults to no password")
enc_parser.add_argument('-o',
                        metavar='outfile', default='-', dest='outfile',
                        help="output file")
enc_parser.add_argument('--comment', '-c',
                        default='',
                        help="header comment")
enc_parser.add_argument('--signature', '-s',
                        default='',
                        help="header signature")
enc_parser.add_argument('--OS', '-O',
                        default=sys.platform,
                        help="force a specific hashing algorithm, defaults to current OS (windows,linux)")
enc_parser.set_defaults(mode=encypher)


args = parser.parse_args()

args.mode(args)

