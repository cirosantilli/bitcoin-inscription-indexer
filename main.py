#!/usr/bin/env python3

# stdlib
import argparse
import binascii
import copy
import heapq
import json
import os
import pathlib
import re
import signal
import sqlite3
import string
import struct
import sys

# Third party
import requests
import bitcoin
from bitcoin.core.script import *
import blockchain_parser.blockchain

# Global state.
outdir = 'data'
bindir = os.path.join(outdir, 'bin')
digits_ascii_int_set = set(ord(c) for c in string.digits)
hexdigits_ascii_int_set = set(ord(c) for c in string.hexdigits)
printable_set = set(string.printable)
CENSORED_TXS = {
    # Hidden wiki.
    'dde7cd8e8f073a525c16c5ee4e4a254f847b7ad6babef257231813166fbef551',
    '4a0088a249e9099d205fb4760c28275d4b8965ac9fd56f5ddf6771cdb0d94f38',

    # ASCII porn
    '9206ec2a41846709a59cafb406dd7b07082bfc27664bbc5c6d4df310c1e1b91f',
    '0aab36554c2ac5ec23747e7f21f75dbe3f16739134cf44953ad7ac98927146d6',
}
JSON_DB_MAX_SIZE_ENTRIES_KEEP = 10000
# tx lists sorted by date.
LIST_NAMES = [
    'atomsea',
    'invalid_tx',
    'jpeg',
    'png',
    'satoshi_uploader',
    'utxo_nonstandard',
]
# tx/size pairs sorted by size.
SIZE_NAMES = [
    'tx_size_bytes',
    'payload_size_in',
    'payload_size_out',
    'payload_size_out_utxo',
    'payload_size_out_utxo_2vals',
    'payload_size_out_op_return',
    'tx_nins',
    'tx_nouts',
    'tx_value',
]
UTXO_DUMP_SQLITE = 'utxodump.sqlite3'

def basename_to_int(basename):
    return int(re.match('(\d+)\.(dat|txt)', basename).group(1))

def download_tx_consts(_txid, index_offset=0, _input=False, **kwargs):
    response = json.loads(requests.get('https://blockchain.info/tx/{}?format=json'.format(_txid)).content.decode('ascii'))
    ret = []
    if 'minlen' in kwargs:
        minlen = kwargs['minlen']
    else:
        minlen = 0
    for out in response['out']:
        hex = bytes.fromhex(out['script'])
        script = blockchain_parser.script.Script.from_hex(hex)
        extract_ops(ret, script, minlen)
    return b''.join(ret)

def download_tx_consts_from_rpc(_txid, btcrpcurl, index_offset=0, _input=False, **kwargs):
    import jsonrpc
    proxy = jsonrpc.ServiceProxy(btcrpcurl)
    tx = proxy.getrawtransaction(_txid, 0)
    return extract_consts(bytes.fromhex(tx), index_offset, _input, **kwargs)

def extract_consts(transaction_rawhex, index_offset, _input, **kwargs):
    tx = blockchain_parser.transaction.Transaction(transaction_rawhex)
    return extract_consts_tx(tx, index_offset, _input, **kwargs)

def extract_consts_tx(tx, index_offset=0, _input=False, **kwargs):
    ret = []
    if _input:
        ios = tx.inputs
    else:
        ios = tx.outputs
    if 'minlen' in kwargs:
        minlen = kwargs['minlen']
    else:
        minlen = 0
    for io in ios[index_offset:]:
        extract_ops(ret, io.script, minlen)
    return b''.join(ret)

def extract_ops(ret, script, minlen):
    try:
        ops = script.operations
        bytes_list = []
        for op in ops:
            if type(op) is not bitcoin.core.script.CScriptOp:
                if type(op) is int:
                    op = bytes([op])
                if len(op) >= minlen:
                    ret.append(op)
    except Exception as e:
        ret.append(script.hex)

def outpath(file_num, pref):
    return os.path.join(outdir, pref, '{:04}'.format(file_num) + '.txt')

def print_ios(blk_num, tx, ios, minlen, output_file, isinput, txno):
    decode = get_ios_bytes(tx, ios, minlen, isinput)
    if decode:
        print_tx(blk_num, tx, output_file, isinput, txno)
        if tx.txid in CENSORED_TXS:
           decode = '[[CIROSANTILLI CENSORED]]\n'
        write('{}'.format(decode), output_file)

class StringSplitter:
    def __init__(self, minlen):
        self.io_bytes = []
        self.has_newline = False
        self.subs_has_newline = False
        self.subs_len = 0
        self.minlen = minlen
        self.prev_subs = []

    def push(self, _bytes):
        """
        Push bytes from one script.
        """
        subs = []
        for b in _bytes:
            s = chr(b)
            if s in printable_set:
                subs.append(s)
                self.subs_len += 1
                if s == '\n':
                    self.subs_has_newline = True
            else:
                if subs and self.subs_len >= self.minlen:
                    if self.subs_has_newline:
                        self.has_newline = True
                    if self.prev_subs:
                        self.io_bytes.append(''.join(self.prev_subs))
                    self.io_bytes.append(''.join(subs))
                    self.prev_subs = []
                subs = []
                self.subs_len = 0
                self.subs_has_newline = False
        if subs and self.subs_len >= self.minlen:
            if self.subs_has_newline:
                self.has_newline = True
            if self.prev_subs:
                self.io_bytes.append(''.join(self.prev_subs))
            self.io_bytes.append(''.join(subs))
            self.prev_subs = []
            subs = []
        self.prev_subs = subs

    def get(self):
        if self.has_newline:
            return ''.join(self.io_bytes)
        else:
            if self.io_bytes:
                return '\n'.join(self.io_bytes) + '\n'
            else:
                return ''

if False:
    ss = StringSplitter(2)
    ss.push(b'ab\ncd')
    ss.push(b'ef')
    assert ss.get() == 'ab\ncdef'

    # blk00099.txt tx 8881a937a437ff6ce83be3a89d77ea88ee12315f37f7ef0dd3742c30eef92dba prevent missing There is.
    #
    # 00000000  22 33 39 36 5c e2 80 9c  54 68 65 72 65 20 69 73  |"396\...There is|
    # 00000010  20 6e 6f 74 68 69 6e 67  20 6c 69 6b 65 20 72 65  | nothing like re|
    # 00000020  74 75 72 6e 69 6e 67 20  74 6f 20 61 20 70 6c 61  |turning to a pla|
    ss = StringSplitter(2)
    ss.push(b'\0a')
    ss.push(b'b\0')
    assert ss.get() == 'a\nb\n'

    ss = StringSplitter(2)
    ss.push(b'a')
    assert ss.get() == ''

    ss = StringSplitter(2)
    ss.push(b'ab')
    assert ss.get() == 'ab\n'

    ss = StringSplitter(2)
    ss.push(b'\0ab')
    assert ss.get() == 'ab\n'

    ss = StringSplitter(2)
    ss.push(b'ab')
    ss.push(b'cd')
    assert ss.get() == 'ab\ncd\n'

    ss = StringSplitter(2)
    ss.push(b'ab')
    ss.push(b'\0')
    assert ss.get() == 'ab\n'

class StringSplitterSimple:
    def __init__(self, minlen):
        self.io_bytes = []
        self.subs_len = 0
        self.minlen = minlen
        self.prev_subs = []

    def push(self, _bytes):
        """
        Push bytes from one script.
        """
        subs = []
        for b in _bytes:
            s = chr(b)
            if s in printable_set:
                subs.append(s)
                self.subs_len += 1
            else:
                if subs and self.subs_len >= self.minlen:
                    if self.prev_subs:
                        self.io_bytes.append(''.join(self.prev_subs))
                    self.io_bytes.append(''.join(subs) + '\n')
                    self.prev_subs = []
                subs = []
                self.subs_len = 0
        if subs and self.subs_len >= self.minlen:
            if self.prev_subs:
                self.io_bytes.append(''.join(self.prev_subs))
            self.io_bytes.append(''.join(subs))
            self.prev_subs = []
            subs = []
        self.prev_subs = subs

    def get(self):
        _bytes = ''.join(self.io_bytes)
        if _bytes and _bytes[-1] != '\n':
            _bytes += '\n'
        return _bytes

if True:
    ss = StringSplitterSimple(2)
    ss.push(b'\0a')
    ss.push(b'b\0')
    assert ss.get() == 'ab\n'

    ss = StringSplitterSimple(2)
    ss.push(b'a')
    assert ss.get() == ''

    ss = StringSplitterSimple(2)
    ss.push(b'ab')
    assert ss.get() == 'ab\n'

    ss = StringSplitterSimple(2)
    ss.push(b'\0ab')
    assert ss.get() == 'ab\n'

    ss = StringSplitterSimple(2)
    ss.push(b'ab')
    ss.push(b'cd')
    assert ss.get() == 'abcd\n'

    ss = StringSplitterSimple(2)
    ss.push(b'ab')
    ss.push(b'\0')
    assert ss.get() == 'ab\n'

    ss = StringSplitterSimple(2)
    ss.push(b'ab\0cd')
    assert ss.get() == 'ab\ncd\n'

    ss = StringSplitterSimple(2)
    ss.push(b'ab\n')
    assert ss.get() == 'ab\n'

    ss = StringSplitterSimple(2)
    ss.push(b'ab\ncd')
    ss.push(b'ef')
    assert ss.get() == 'ab\ncdef\n'

def get_ios_bytes(tx, ios, minlen, isinput):
    global json_db
    has_op_return = False
    ss = StringSplitterSimple(minlen);
    payload_size = 0
    is_2vals = True
    consts_bytes_list = []
    satoshi_bytes_list = []
    atomsea_bytes_list = []
    op_signatures = []
    if not isinput:
        total_value = 0
        if len(ios) > 0:
            first_val = ios[0].value
    for ioidx, io in enumerate(ios):
        script = io.script
        if isinput and tx.is_coinbase():
            # Arbitrary data.
            bytes_list = [io.script.hex]
        else:
            try:
                ops = script.operations
                op_signature = []
                bytes_list = []
                for op in ops:
                    if type(op) == bitcoin.core.script.CScriptOp:
                        op_signature.append(bitcoin.core.script.OPCODE_NAMES[op])
                    else:
                        op_signature.append(None)
                        bytes_list.append(op)
                op_signature = tuple(op_signature)
                op_signatures.append(op_signature)
                if not op_signature in json_db['known_op_signatures']:
                    json_db['known_op_signatures'][op_signature] = {
                        'count': 0,
                        'sample': tx.txid,
                        'ioidx': ioidx,
                    }
                json_db['known_op_signatures'][op_signature]['count'] += 1
                if ops and ops[0] == bitcoin.core.script.OP_RETURN:
                    has_op_return = True
            except:
                # blk 88
                # https://blockchain.info/tx/ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767?format=json
                # Others:
                # - 6f8a70aac37786b1f619d40250b8bca1a1f6da487146a7e81091f611068a23ef
                # first output. It looks like you can always make invalid output scripts of
                # some type that throw, so we just to ignore them (or log them if not too common.
                # bitcoin.core.script.CScriptTruncatedPushDataError: PUSHDATA(1): truncated data
                # Also they are likely not spendable, so not much can come of this except
                # deducing identidies of developers.
                serialize_list('invalid_tx', (tx.txid, ioidx))
                bytes_list = [io.script.hex]
                op_signatures.append(tuple())
                if tx.txid == 'fa735229f650a8a12bcf2f14cca5a8593513f0aabc52f8687ee148c9f9ab6665':
                    print('ok')
        for _bytes in bytes_list:
            if type(_bytes) is int:
                # It seems to convert 1 byte literals like OP_1, OP_2 etc. to ints instead of bytes
                # CScript([OP_DUP, OP_HASH160, 0, OP_EQUALVERIFY, OP_CHECKSIG])
                # "out": ["script":"76a90088ac"
                # We just add them to the payload. This could lead to errors. E.g. Satoshi Downloader
                # ignores those from payload.
                _bytes = bytes([_bytes])
            else:
                if len(_bytes) >= 20:
                    satoshi_bytes_list.append(_bytes)
            payload_size += len(_bytes)
            consts_bytes_list.append(_bytes)
            if not isinput and io.value == first_val:
                atomsea_bytes_list.append(_bytes)
            ss.push(_bytes)
        if not isinput:
            total_value += io.value
            if ioidx < len(ios) - 1 and io.value != first_val:
                is_2vals = False
    # Raw consts index.
    consts_bytes = b''.join(consts_bytes_list)
    if consts_bytes.startswith(bytes.fromhex('FFD8FF')):
        serialize_list('jpeg', (tx.txid,))
    if consts_bytes.startswith(bytes.fromhex('89504E470D0A1A0A')):
        serialize_list('png', (tx.txid,))

    # Satoshi consts index.
    satoshi_bytes = b''.join(satoshi_bytes_list)
    satoshi_bytes_len = len(satoshi_bytes)
    if satoshi_bytes_len > 8:
        length = struct.unpack('<L', satoshi_bytes[0:4])[0]
        checksum = struct.unpack('<L', satoshi_bytes[4:8])[0]
        satoshi_bytes_data = satoshi_bytes[8:8+length]
        if (
            # There are some transactions with a 0 hash, e.g.
            # https://www.blockchain.com/btc/tx/2c637592a4b4a95cf4b19260730c66de540d7d3b14d8d352de591c5ee6eac0fc
            # and the crc of empty is 0.
            length > 0 and
            len(satoshi_bytes_data) >= length and
            checksum == binascii.crc32(satoshi_bytes_data)
        ):
            serialize_list('satoshi_uploader', (tx.txid,))

    # Atomsea index
    if not isinput:
        atomsea_bytes = b''.join(atomsea_bytes_list)
        if len(atomsea_bytes) > 64 + 1 + 1 + 1 + 64 + 2:
            text_txid = atomsea_bytes[:64]
            if (
                set(text_txid) <= hexdigits_ascii_int_set and
                not atomsea_bytes[64] in hexdigits_ascii_int_set
            ):
                i = 65
                while atomsea_bytes[i] in digits_ascii_int_set:
                    i += 1
                if i > 65:
                    i += 1
                    if text_txid == atomsea_bytes[i: i + 64]:
                        i += 64
                        if atomsea_bytes[i: i + 2] == b'\r\n':
                            serialize_list('atomsea', (tx.txid,))

    if isinput:
        _type = 'in'
    else:
        _type = 'out'
    update_size('payload_size_' + _type, payload_size, tx.txid)
    if not isinput and has_op_return:
        update_size('payload_size_out_op_return', payload_size, tx.txid)

    # UTXO stuff.
    outs_in_utxo = get_outs_in_utxo(tx.txid)
    len_not_utxo = len(ios) - len(outs_in_utxo)
    if not isinput:
        if len_not_utxo == 0 or (len_not_utxo == 1 and len(ios) > 1):
            update_size('payload_size_out_utxo', payload_size, tx.txid)
            if is_2vals:
                update_size('payload_size_out_utxo_2vals', payload_size, tx.txid)
        for out_in_utxo in outs_in_utxo:
            if out_in_utxo[4] == 'non-standard':
                vout = out_in_utxo[2]
                op_signature = op_signatures[vout]
                if len(op_signature) > 0 and op_signature[0] != 'OP_RETURN':
                    # TODO add ios[vout].value here as well, some useless 0 value outs present.
                    # e.g. https://www.blockchain.com/btc/tx/90d089b07d7a9f84adf1be6c9de5422b24f7eef4aa09d18444bcc81b47862a98?page2=62 vout 308.
                    serialize_list('utxo_nonstandard', (tx.txid, vout) + op_signature)

    update_size('tx_n' + _type + 's', len(ios), tx.txid)
    if not isinput:
        update_size('tx_value', total_value, tx.txid)
    return ss.get()

def get_outs_in_utxo(txid):
    """
    Return the outputs of this transaction that are in UTXO.
    """
    global utxodb
    if utxodb is None:
        return []
    else:
        return utxodb.execute(
            'SELECT * FROM utxo WHERE txid = ?', (txid,)
        ).fetchall()

def print_tx(blk_num, tx, output_file, isinput, txno):
    global first_print_in_file_in
    global first_print_in_file_out
    global first_print_in_blk_in
    global first_print_in_blk_out
    if isinput:
        if not first_print_in_file_in:
            write('\n', output_file)
        if first_print_in_blk_in:
            # write('blk {}\n\n'.format(blk_num), output_file)
            pass
        first_print_in_file_in = False
        first_print_in_blk_in = False
    else:
        if not first_print_in_file_out:
            write('\n', output_file)
        if first_print_in_blk_out:
            # write('blk {}\n\n'.format(blk_num), output_file)
            pass
        first_print_in_file_out = False
        first_print_in_blk_out = False
    if output_file is None:
        if isinput:
            pref = 'in '
        else:
            pref = 'out '
    else:
        pref = ''
    write('tx {}{}\n'.format(pref, tx.txid), output_file)

def strings_n(_bytes, minlen=20):
    ret = []
    subs = []
    for b in _bytes:
        s = chr(b)
        if s in printable_set:
            subs.append(s)
        else:
            if len(subs) >= minlen:
                ret.append(''.join(subs))
            subs = []
    if subs and len(subs) >= minlen:
        ret.append(''.join(subs))
    return '\n'.join(ret)

def write(s, output_file, **kwargs):
    if output_file is None:
        print(s, end='', **kwargs)
    else:
        output_file.write(s)


## Size things on db.json.

def serialize_list(name, values):
    global list_db
    list_db[name].append([str(v) for v in values])

def serialize_size(name):
    global size_db
    heap = size_db[name]
    with open(os.path.join(outdir, name), 'w') as f:
        for entry in sorted(heap, reverse=True):
            f.write('{} {}\n'.format(entry[1], entry[0]))
        f.flush()

def unserialize_size(name):
    global size_db
    heap = []
    with open(os.path.join(outdir, name), 'r') as f:
        for line in f:
            entry = line.split()
            heapq.heappush(heap, (int(entry[1]), entry[0]))
        f.flush()
    size_db[name] = heap

def update_size(name, size, txid):
    global size_db
    heap = size_db[name]
    if len(heap) < JSON_DB_MAX_SIZE_ENTRIES_KEEP:
        heapq.heappush(heap, (size, txid))
    else:
        if size > heap[0][0]:
            heapq.heappop(heap)
            heapq.heappush(heap, (size, txid))

if __name__ == '__main__':
    list_db = {}
    list_db_files = {}
    size_db = {}
    exit_signal = False
    def signal_handler(sig, frame):
        """
        This is needed because the JSON DB gets larger and takes
        a second to finish writing fully to disk.
        """
        global exit_signal
        exit_signal = True
        print('quitting')
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # CLI arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--blocks-per-file',
        type=int,
        default=1000,
    )
    parser.add_argument(
        '-e',
        '--end-blk',
        type=int,
        default=None,
        help='''The last block height is the one before this number (N-1, exclusive)'''
    )
    parser.add_argument(
        '--minlen',
        type=int,
        default=20,
        help='''Minimum length of strings to find'''
    )
    parser.add_argument(
        '-s',
        '--start-blk',
        type=int,
        default=None,
        help='''Start searching for ascii at block height, skip any earlier blocks'''
    )
    parser.add_argument(
        '--stdout',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        'datadir',
        nargs='?',
        default=os.path.join(pathlib.Path.home(), '.bitcoin', 'blocks'),
        help='/path/to/.bitcoin/blocks'
    )
    args = parser.parse_args()

    if os.path.exists(UTXO_DUMP_SQLITE):
        utxodb = sqlite3.connect(UTXO_DUMP_SQLITE)
    else:
        utxodb = None

    # Main.
    stdout_mode = args.stdout
    if not stdout_mode:
        if not os.path.exists(outdir):
            os.mkdir(outdir)
            os.mkdir(os.path.join(outdir, 'in'))
            os.mkdir(os.path.join(outdir, 'out'))
    known_op_signatures_path = os.path.join(outdir, 'known_op_signatures.json')
    if os.path.exists(known_op_signatures_path):
        with open(known_op_signatures_path, 'r') as f:
            known_op_signatures_raw = json.load(f)
        known_op_signatures = {}
        for known_op_signature in known_op_signatures_raw:
            known_op_signatures[tuple(known_op_signature['sig'])] = {
                'sample': known_op_signature['sample'],
                'ioidx': known_op_signature['ioidx'],
                'count': known_op_signature['count'],
            }
        json_db = {
            'known_op_signatures': known_op_signatures,
        }
        for name in SIZE_NAMES:
            unserialize_size(name)
        for name in LIST_NAMES:
            list_db[name] = []
            list_db_files[name] = open(os.path.join(outdir, name), 'a')
    else:
        json_db = {
            # https://bitcoin.stackexchange.com/questions/5883/is-there-a-listing-of-strange-or-unusual-scripts-found-in-transactions
            # It would be great to have counts. Also gotta think better about input scripts and multiple outputs.
            'known_op_signatures': {},
        }
        for name in LIST_NAMES:
            list_db[name] = []
            list_db_files[name] = open(os.path.join(outdir, name), 'w')
        for name in SIZE_NAMES:
            size_db[name] = []
    blockchain = blockchain_parser.blockchain.Blockchain(args.datadir)
    first_print_in_file_in = True
    first_print_in_file_out = True
    last_file_num = -1
    if args.start_blk is None:
        if stdout_mode:
            start_blk = 0
        else:
            outs = os.listdir(os.path.join(outdir, 'in'))
            if outs:
                start_blk = basename_to_int(sorted(outs)[-1]) * args.blocks_per_file
            else:
                start_blk = 0
    else:
        start_blk = args.start_blk
    input_file = None
    output_file = None
    for block in blockchain.get_ordered_blocks(
        os.path.join(args.datadir, 'index'),
        cache='cache.pkl',
        start=start_blk,
        end=args.end_blk
    ):
        if exit_signal:
            break
        height = block.height
        cur_file_num = height // args.blocks_per_file
        if last_file_num < cur_file_num and not stdout_mode:
            if input_file is not None:
                input_file.close()
                output_file.close()

                # Redump indexes.
                known_op_signatures = []
                for key in json_db['known_op_signatures']:
                    known_op_signatures.append({
                        'sig': key,
                        'sample': json_db['known_op_signatures'][key]['sample'],
                        'ioidx': json_db['known_op_signatures'][key]['ioidx'],
                        'count': json_db['known_op_signatures'][key]['count'],
                    })
                known_op_signatures.sort(key=lambda x: x['count'], reverse=True)
                json_db_dump = copy.copy(json_db)
                json_db_dump['known_op_signatures'] = known_op_signatures
                for name in LIST_NAMES:
                    for entry in list_db[name]:
                        list_db_files[name].write(' '.join(entry) + '\n')
                        list_db_files[name].flush()
                    list_db[name] = []
                for name in SIZE_NAMES:
                    serialize_size(name)
                for key in json_db_dump:
                    with open(os.path.join(outdir, key + '.json'), 'w') as f:
                        json.dump(json_db_dump[key], f, indent=2, sort_keys=True)
                os.sync()

            input_file = open(outpath(cur_file_num, 'in'), 'w')
            output_file = open(outpath(cur_file_num, 'out'), 'w')
            print('{}'.format(cur_file_num), file=sys.stderr)
            first_print_in_file_in = True
            first_print_in_file_out = True
            last_file_num = cur_file_num
        first_print_in_blk_in = True
        first_print_in_blk_out = True
        for txno, tx in enumerate(block.transactions):
            if exit_signal:
                break
            update_size('tx_size_bytes', tx.size, tx.txid)
            print_ios(height, tx, tx.inputs, args.minlen, input_file, True, txno)
            print_ios(height, tx, tx.outputs, args.minlen, output_file, False, txno)
    for name in LIST_NAMES:
        list_db_files[name].close()
    if not stdout_mode and input_file is not None:
        input_file.close()
        output_file.close()
