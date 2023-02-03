#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import apksigtool

POC_BLOCK_ID = 0x506f4342


def extract_poc(apkfile: str, payloadfile: str) -> None:
    _, sig_block = apksigtool.extract_v2_sig(apkfile)
    blk = apksigtool.parse_apk_signing_block(sig_block, allow_nonzero_verity=True)
    payload = None
    for pair in blk.pairs:
        if isinstance(pair.value, apksigtool.UnknownBlock) and pair.id == POC_BLOCK_ID:
            payload = pair.value.raw_data
        elif isinstance(pair.value, apksigtool.NonZeroVerityPaddingBlock):
            payload = pair.value.raw_data.rstrip(b"\x00")
            if payload.endswith(b"\x00EOF"):
                payload = payload[:-3]
    if payload:
        with open(payloadfile, "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="extract_poc.py")
    parser.add_argument("apkfile", metavar="APKFILE")
    parser.add_argument("payloadfile", metavar="PAYLOADFILE")
    args = parser.parse_args()
    extract_poc(args.apkfile, args.payloadfile)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
