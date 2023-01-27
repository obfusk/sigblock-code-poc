#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import apksigtool
import dataclasses

from dataclasses import dataclass
from typing import ClassVar

POC_BLOCK_ID = 0x506f43


@dataclass(frozen=True)
class PoCBlock(apksigtool.Block):
    payload: bytes

    PAIR_ID: ClassVar[int] = POC_BLOCK_ID

    def dump(self) -> bytes:
        return self.payload


def add_poc(apkfile: str, payloadfile: str) -> None:
    with open(payloadfile, "rb") as fh:
        payload = fh.read()
    _, sig_block = old_v2_sig = apksigtool.extract_v2_sig(apkfile)
    blk = apksigtool.parse_apk_signing_block(sig_block)
    poc_pair = apksigtool.Pair.from_block(PoCBlock(payload))
    blk_poc = dataclasses.replace(blk, pairs=blk.pairs + (poc_pair,))
    apksigtool.replace_apk_signing_block(apkfile, blk_poc.dump(), old_v2_sig=old_v2_sig)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="add_poc.py")
    parser.add_argument("apkfile", metavar="APKFILE")
    parser.add_argument("payloadfile", metavar="PAYLOADFILE")
    args = parser.parse_args()
    add_poc(args.apkfile, args.payloadfile)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
