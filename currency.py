#!/usr/bin/env python3

import hashlib
import struct
import time

from binascii import hexlify as hl
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np


def index_part(fname, start, end):
    out = b''
    with open(fname, 'rb') as f:
        f.seek(start)
        p = 0

        buf = f.read(end - start)
        while buf[p:]:
            prefix, length, sec, nsec = struct.unpack_from('4siqq', buf, p)
            data_p = 24  # 4:prefix + 4:length + 8:sec + 8:nsec

            ##### get key TODO
            key = b''

            ##### get value
            hash = hashlib.md5()
            hash.update(buf[p + data_p:
                            p + data_p + length - 16  # without sec & nsec
                        ])
            hashval = hash.digest()

            # 1. [8]  timestamp
            # 2. [16] binary md5 value
            # 3, [8]  position in the original file
            val = struct.pack('q16sq', sec * 10 ** 9 + nsec, hashval, p)

            # concat
            out += key
            out += val

            p += 8 + length
    return out


def to_index_file(fname):
    file = Path(fname)

    ### Splite file into smaller part, index it in multiple process
    filesize = file.stat().st_size
    start = 8
    points = np.linspace(start, filesize, num=10, endpoint=False)
    new_points = []
    with open(file, 'rb') as f:
        for p in points:
            buf = f.read(1024 * 64)
            new_pos = buf.find(b'####')
            new_points.append(p + new_pos)

    start_points = new_points
    end_points = new_points.copy()
    end_points.pop(0)
    end_points.append(filesize)
    params = zip(start_points, end_points)

    with ProcessPoolExecutor() as exe:
        outindex = b''

        for ret in exe.map(index_part, params):
            outindex += ret

        with open(fname.name + '.index', 'rb') as f:
            f.write(outindex)


INDEX_DTYPE = np.dtype([
    # key, total 13B
    ('msgtype', np.dtype('i4')),

    # the detailed key is depend on msg type
    ('key', np.dtype('U24')),

    # value, total 20B
    ('tsp', np.dtype('i8')),
    ('hash', np.dtype('U16')),
    ('pos', np.dtype('i8')),
])


def process(fname_fpga, fname_mdgw):
    msg_all = [
        300111,
        300191,
        300192,
    ]
    fpga = np.fromfile(fname_fpga, dtype=INDEX_DTYPE)
    mdgw = np.fromfile(fname_mdgw, dtype=INDEX_DTYPE)
    for msg in msg_all:
        idx_fpga = np.where(fpga['msgtype'] == msg)
        idx_mdgw = np.where(mdgw['msgtype'] == msg)

        d_fpga = fpga[idx_fpga]
        d_mdgw = mdgw[idx_mdgw]

        keys_common, ind_fpga, ind_mdgw = np.intersect1d(d_fpga['key'], d_mdgw['key'], return_indices=True)

        keys_more = np.setdiff1d(d_fpga['key'], d_mdgw['key'])
        keys_more, indm_fpga, indm_mdgw = np.intersect1d(d_fpga['key'], keys_more, return_indices=True)

        keys_less = np.setdiff1d(d_mdgw['key'], d_fpga['key'])
        keys_less, indl_fpga, _ = np.intersect1d(d_mdgw['key'], keys_less, return_indices=True)

        com_fpga, com_mdgw = fpga[ind_fpga], mdgw[ind_mdgw]
        fmore_fpga = fpga[indm_fpga]
        fless_fpga = mdgw[indl_fpga]

        keys_correct, ind_correct_fpga, ind_correct_mdgw = np.intersect1d(com_fpga['hash'], com_mdgw['hash'])
        keys_error = np.setdiff1d(com_fpga['hash'], keys_correct)
        d_fpga_correct = com_fpga[ind_correct_fpga]
        d_mdgw_correct = com_mdgw[ind_correct_mdgw]
        idx_faster = d_fpga_correct['tsp'] < d_mdgw_correct[ind_correct_mdgw]
        idx_slower = np.logical_not(idx_faster)
        time_diff = d_mdgw_correct[ind_correct_mdgw] - d_fpga_correct['tsp']

        n_common = com_fpga.shape[0]
        n_fmore = fmore_fpga.shape[0]
        n_fless = fless_fpga.shape[0]
        n_faster = sum(idx_faster)
        n_slower = sum(idx_slower)


def main():
    # process('fpga.binlog')

    dt = np.dtype([
        ('msgtype', np.int32),
        ('key', np.dtype('U4')),
        ('hash', np.dtype('U66')),

    ])
    fpga = np.array([
        (300192, 'key2', 'hash2 '),
        (300192, 'key3', 'hash33'),
        (300192, 'key4', 'hash4 '),
        (300192, 'key1', 'hash1 '),
        (300192, 'key5', 'hash5 '),
        (300192, 'key6', 'hash6 '),
        (300192, 'key8', 'hash8 '),
    ], dtype=dt)

    mdgw = np.array([
        (300192, 'key1', 'hash1 '),
        (300192, 'key2', 'hash2 '),
        (300192, 'key3', 'hash32'),
        (300192, 'key5', 'hash5 '),
        (300192, 'key6', 'hash6 '),
        (300192, 'key7', 'hash7 '),
        (300192, 'key8', 'hash8 '),
    ], dtype=dt)

    idx_fpga = np.where(fpga['msgtype'] == 300192)
    idx_mdgw = np.where(mdgw['msgtype'] == 300192)

    d_fpga = fpga[idx_fpga]
    d_mdgw = mdgw[idx_mdgw]

    keys_common, ind_fpga, ind_mdgw = np.intersect1d(d_fpga['key'], d_mdgw['key'], return_indices=True)

    keys_more = np.setdiff1d(d_fpga['key'], d_mdgw['key'])
    keys_more, indm_fpga, indm_mdgw = np.intersect1d(d_fpga['key'], keys_more, return_indices=True)

    keys_less = np.setdiff1d(d_mdgw['key'], d_fpga['key'])
    keys_less, indl_fpga, _ = np.intersect1d(d_mdgw['key'], keys_less, return_indices=True)

    print(keys_common)
    print(keys_more)
    print(keys_less)

    com_fpga, com_mdgw = fpga[ind_fpga], mdgw[ind_mdgw]
    fmore_fpga = fpga[indm_fpga]
    fless_fpga = mdgw[indl_fpga]

    keys_correct, ind_correct_fpga, ind_correct_mdgw = np.intersect1d(com_fpga['hash'], com_mdgw['hash'],
                                                                      return_indices=True)
    d_fpga_correct = com_fpga[ind_correct_fpga]
    d_mdgw_correct = com_mdgw[ind_correct_mdgw]
    print(d_fpga_correct.shape[0])
    print(d_mdgw_correct.shape[0])


if __name__ == '__main__':
    main()

