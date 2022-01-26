#!/usr/bin/env python3

import argparse
import os
import struct
import sqlite3

import plyvel

import main

def decode_varint(data):
    '''
    https://bitcoin.stackexchange.com/questions/121888/what-is-the-data-format-layout-for-txindex-leveldb-values/121889#121889
    https://bitcointalk.org/index.php?topic=1068721.0
    '''
    i = 0
    ret = 0
    while True:
        b = data[i]
        ret += b & 0x7F
        if b & 0x80:
            b += 1
        else:
            return (ret, i + 1)
        ret <<= 7
        i += 1

parser = argparse.ArgumentParser(description='Convert txindex LevelDB to an indeed SQLite database. TODO: whats the exact format of txindex? https://bitcoin.stackexchange.com/questions/28168/what-are-the-keys-used-in-the-blockchain-leveldb-ie-what-are-the-keyvalue-pair/29418#comment139491_29418')
parser.add_argument(
    '-d',
    '--datadir',
    default=None,
    help='Path to .bitcoin/blocks'
)
args = parser.parse_args()
datadir = main.init_datadir(args.datadir)
ldb = plyvel.DB(os.path.join(os.path.split(datadir)[0], os.path.join('indexes', 'txindex')), compression=None)
def ldb_get():
    i = 0
    nerrs = 0
    for key, value in ldb:
        if key[0:1] == b't':
            if i % 1000000 == 0:
                print(i//1000000)
            txid = bytes(reversed(key[1:])).hex()
            total_off = 0
            file, off = decode_varint(value)
            total_off += off
            blk_off, off = decode_varint(value[total_off:])
            total_off += off
            tx_off, off = decode_varint(value[total_off:])
            #total_off += off
            #assert total_off == len(value)
            #print((txid, file, blk_off, tx_off))
            yield (txid, file, blk_off + tx_off)
            i += 1
connection = sqlite3.connect('txindex.sqlite3')
cursor = connection.cursor()
cursor.execute('DROP TABLE IF EXISTS t')
cursor.execute('CREATE TABLE t (txid INT, file INT, offset INT)')
cursor.executemany('INSERT INTO t VALUES (?, ?, ?)', ldb_get())
connection.commit()
connection.close()
