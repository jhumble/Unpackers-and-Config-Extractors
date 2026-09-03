#!/usr/bin/env python3
"""
Unpacker for the "LABZ" staging container used by the LabZ sideload loader
(AppVIsvSubsystems64.dll, delivered alongside a genuine Microsoft-signed
WinWord.exe and observed staging PureCrypter).

Container layout, little-endian throughout:

    "LABZ" | u32 version | u32 entry_count
    then entry_count records of:
        u16 name_len | name (utf-8) | u32 data_len | data

Entries are stored plain -- no per-entry compression or encryption. The whole
container is RC4'd as a single blob on disk under .\\cache\\<rand>_<buildid>.bin,
so one RC4 pass over the file yields the entire tree.

The container carries both the Python bootstrap and the blob that bootstrap
consumes, so stage 2 can be recovered without any external key: lift the
32-byte _K list out of the bootstrap, RC4 the sibling .dat, then zlib-inflate.

The unpacked tree is a stock CPython 3.11 embeddable distribution plus two
encrypted blobs. Exactly one .py entry is present -- that is the entrypoint the
loader passes to python.exe on the command line.

Reference samples, both on VirusTotal (first seen 2026-09-01):

    8f0d4cd3fbd97fec43b137480cd793f172abbf4cc4f88ed631f2e66cd8293e36
        Delivery zip, 29/76. Start here. Contains the loader DLL, a genuine
        Microsoft-signed WinWord.exe as the sideload host, and
        cache/kr5vzbs_7f2bb20d.bin -- the RC4'd container this tool consumes.
    b759b09dbf28bd1340942353194051d9cf1cd3a0acfa7de68c6277d64eb67bd0
        AppVIsvSubsystems64.dll, 32/76. The loader; builds the outer RC4 key
        at runtime.

Neither the packed container (sha256 0131cf42a2de96c0fc0d2a12fb99f728fbbc8353
692b8deaa8c1ec5b672eec4d) nor its decrypted form (sha256 c64bea6b895ff3212cc7
5a850a44e3b62c2781051f3c98848b08e5e4f3e9794b) is on VT independently -- pull
the zip and take the cache/ member.

The outer key was not recovered statically for that sample, so to reach a
decrypted container you currently need to lift the key from the DLL or dump the
container from a detonation. Everything from the container inward is static.
"""
import logging
import os
import re
import struct
import sys
import zlib
from argparse import ArgumentParser
from pathlib import Path

repo_root = Path(os.path.realpath(__file__)).parent.parent.absolute()
sys.path.append(os.path.join(repo_root, 'lib'))
from rc4 import CustomRC4
from utils import configure_logger, entropy, human_size

MAGIC = b'LABZ'


def parse_args():
    usage = "unpack.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument("-d", "--dump", dest="dump_dir", action="store", default='unpacked',
        help="Dump path for unpacked entries")
    arg_parser.add_argument('-v', '--verbose', action='count', default=0,
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument('-k', '--rc4-key', dest='rc4_key', action='store', default=None,
        help='Hex RC4 key for the outer cache blob. Only needed when the input is still '
             'encrypted; the key is built at runtime by the loader DLL. Omit for an '
             'already-decrypted container.')
    arg_parser.add_argument('-l', '--list', dest='list_only', action='store_true', default=False,
        help='List entries without writing anything')
    arg_parser.add_argument('files', nargs='+')
    return arg_parser.parse_args()


def parse_labz(data):
    """Yield (name, payload) for every entry. Raises ValueError on a bad container."""
    if data[:4] != MAGIC:
        raise ValueError('missing LABZ magic')
    version, count = struct.unpack_from('<II', data, 4)
    logging.info(f'LABZ v{version}, {count} entries, {human_size(len(data))}')
    off = 12
    entries = []
    for i in range(count):
        if off + 2 > len(data):
            raise ValueError(f'truncated at entry {i}: no name length')
        name_len, = struct.unpack_from('<H', data, off)
        off += 2
        name = data[off:off + name_len].decode('utf-8', 'replace')
        off += name_len
        if off + 4 > len(data):
            raise ValueError(f'truncated at entry {i} ({name}): no data length')
        data_len, = struct.unpack_from('<I', data, off)
        off += 4
        if off + data_len > len(data):
            raise ValueError(f'truncated at entry {i} ({name}): want {data_len}, '
                             f'have {len(data) - off}')
        entries.append((name, data[off:off + data_len]))
        off += data_len
    if off != len(data):
        logging.warning(f'{len(data) - off} trailing bytes after last entry')
    return entries


def find_bootstrap_key(source):
    """Lift the 32-byte _K = bytes([...]) key list out of the Python bootstrap."""
    m = re.search(rb'_K\s*=\s*bytes\s*\(\s*\[([0-9,\s]+)\]', source)
    if not m:
        return None
    return bytes(int(v) for v in m.group(1).split(b',') if v.strip())


def unwrap_stage2(blob, key):
    """RC4 then zlib-inflate, the transform the bootstrap applies to its .dat sibling."""
    return zlib.decompress(bytes(CustomRC4(key).decrypt(blob)))


def process(path, args):
    data = open(path, 'rb').read()
    logging.info(f'{path}: {human_size(len(data))}, entropy {entropy(data):.3f}')

    if data[:4] != MAGIC:
        if not args.rc4_key:
            logging.error(f'{path}: not a LABZ container and no --rc4-key given. The outer '
                          f'cache blob is RC4-encrypted; supply the key or decrypt it first.')
            return
        key = bytes.fromhex(args.rc4_key)
        logging.info(f'decrypting outer blob with {len(key)}-byte RC4 key')
        data = bytes(CustomRC4(key).decrypt(data))
        if data[:4] != MAGIC:
            logging.error(f'{path}: RC4 with the supplied key did not yield a LABZ container')
            return

    entries = parse_labz(data)

    dump_dir = None
    if not args.list_only:
        dump_dir = os.path.join(args.dump_dir, Path(path).name)
        os.makedirs(dump_dir, exist_ok=True)

    for i, (name, payload) in enumerate(entries):
        logging.info(f'  [{i:2}] {name:<45} {len(payload):>10}')
        if dump_dir:
            out = os.path.join(dump_dir, name)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, 'wb') as fp:
                fp.write(payload)

    # The bootstrap and the blob it decrypts both live in the container, so stage 2
    # is recoverable with no external key material.
    scripts = [(n, d) for n, d in entries if n.lower().endswith('.py')]
    blobs = [(n, d) for n, d in entries if n.lower().endswith('.dat')]
    if not scripts or not blobs:
        logging.warning('no .py/.dat pair in container; skipping stage 2 recovery')
        return

    for script_name, script in scripts:
        key = find_bootstrap_key(script)
        if not key:
            logging.warning(f'{script_name}: no _K key list found')
            continue
        logging.info(f'{script_name}: recovered {len(key)}-byte RC4 key')
        for blob_name, blob in blobs:
            try:
                stage2 = unwrap_stage2(blob, key)
            except Exception as err:
                logging.debug(f'{blob_name}: {err}')
                continue
            logging.info(f'{blob_name} -> stage 2, {human_size(len(stage2))}')
            if dump_dir:
                out = os.path.join(dump_dir, blob_name + '.stage2.py')
                with open(out, 'wb') as fp:
                    fp.write(stage2)
                logging.info(f'wrote {out}')


if __name__ == '__main__':
    args = parse_args()
    configure_logger(args.verbose)
    for path in args.files:
        try:
            process(path, args)
        except Exception as err:
            logging.error(f'{path}: {err}')
