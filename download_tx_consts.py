#!/usr/bin/env python3

import argparse
import os
import struct
from pathlib import Path
from binascii import crc32

import blockchain_parser.blockchain
import plyvel

import main

parser = argparse.ArgumentParser(
    description='Downlod transaction script constants from a selected source'
)
parser.add_argument(
    '-d',
    '--datadir',
    default=None,
    help='Path to .bitcoin/blocks'
)
parser.add_argument(
    '--images',
    default=False,
    action='store_true',
    help='Download all indexed JPEG and PNG raw images'
)
parser.add_argument(
    '--satoshi-all',
    default=False,
    action='store_true',
    help='Download all indexed satoshi uploader transactions'
)
parser.add_argument(
    '--satoshi',
    default=False,
    action='store_true',
    help='Use the encoding from: https://gist.github.com/cirosantilli/7e9af25f4f742b97074c10b9c5816f3d'
)
parser.add_argument(
    '-s',
    '--source',
    default='blockchain.info',
    choices=['blockchain.info', 'parse', 'rpc'],
    help='Where to download the data from'
)
parser.add_argument(
    '-i',
    '--input',
    default=False,
    action='store_true',
    help='Download input transaction payloads instead of the default output payloads'
)
parser.add_argument('txids', nargs='*')
args = parser.parse_args()
args.datadir = main.init_datadir(args.datadir)

if args.source == 'parse':
    blockchain = blockchain_parser.blockchain.Blockchain(args.datadir)
    db = plyvel.DB(os.path.join(args.datadir, 'index'), compression=None)

def download(txid, **kwargs):
    global args
    for out_not_in in [True, False]:
        if not 'ext' in kwargs:
            kwargs['ext'] = '.bin'
        if not 'outdir' in kwargs:
            kwargs['outdir'] = '.'
        if not 'satoshi' in kwargs:
            kwargs['satoshi'] = False
        subkwargs = {}
        if kwargs['satoshi']:
            subkwargs['minlen'] = 20
        iosuf = '' if out_not_in else '-in'
        outpath = os.path.join(kwargs['outdir'], txid + iosuf + kwargs['ext'])
        if not os.path.exists(outpath):
            print(txid)
            if args.source == 'blockchain.info':
                data = main.download_tx_consts(txid, _input=args.input, out_not_in=out_not_in, **subkwargs)
            elif args.source == 'parse':
                data = main.extract_consts_tx(blockchain.get_transaction(txid, db), _input=args.input, **subkwargs)
            elif args.source == 'rpc':
                data = main.download_tx_consts_from_rpc(txid, os.environ['BTCRPCURL'], _input=args.input, **subkwargs)
            if kwargs['satoshi']:
                length = struct.unpack('<L', data[0:4])[0]
                checksum = struct.unpack('<L', data[4:8])[0]
                data = data[8:8+length]
                assert checksum == crc32(data)
            with open(outpath, 'bw') as f:
                f.write(data)

if not os.path.exists(main.bindir):
    os.mkdir(main.bindir)

for txid in args.txids:
    download(txid, outdir=main.bindir, satoshi=args.satoshi)

if args.satoshi_all:
    with open(os.path.join(main.outdir, 'satoshi_uploader'), 'r') as f:
        for line in f:
            download(line.rstrip(), satoshi=True, outdir=main.bindir)

if args.images:
    for fname, ext in [
        ('gif', '.gif'),
        ('jpeg', '.jpg'),
        ('mp4', '.mp4'),
        ('ogg', '.ogg'),
        ('pdf', '.pdf'),
        ('png', '.png'),
        ('webp', '.webp'),
        ('cryptograffiti', '.bin'),
    ]:
        with open(os.path.join(main.outdir, fname), 'r') as f:
            for line in f:
                download(line.rstrip(), outdir=main.bindir, ext=ext)
