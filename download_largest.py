#!/usr/bin/env python

import argparse
import itertools
import json
import os

import main

parser = argparse.ArgumentParser(description='Downlod all largest transactions')
parser.add_argument('--db', default=main.json_db_path, help='Path to db.json')
parser.add_argument('-n', '--max', default=100, type=int, help='How many to download')
parser.add_argument('type', default='payload_size_out', nargs='?')
args = parser.parse_args()

outdir = os.path.join(main.outdir, 'largest')
if not os.path.exists(outdir):
    os.mkdir(outdir)

if args.db is None:
    db_path = main.json_db_path
else:
    db_path = args.db
with open(db_path, 'r') as f:
    json_db = json.load(f)

for _size, _txid in itertools.islice(json_db[args.type], args.max):
    outpath = os.path.join(outdir, _txid + '.bin')
    if not os.path.exists(outpath):
        print(_txid)
        data = main.download_tx_consts(_txid)
        with open(outpath, 'bw') as f:
            f.write(data)
