#!/usr/bin/env python3
"""Bounded external x86-64 semantic qualification for FRE native images."""

from __future__ import annotations

import argparse
import itertools
import struct
from dataclasses import dataclass

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RFLAGS,
    UC_X86_REG_RIP,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R9,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

MAGIC = b"FREQX64\x01"
CODE = 0x10_0000
HAYSTACK = 0x40_0000
RESULT = 0x50_0000
STACK = 0x60_0000
STOP = 0x70_0000
PAGE = 0x1000


@dataclass(frozen=True)
class Record:
    kind: int
    tier: int
    anchors: int
    class_bits: bytes
    pattern: bytes
    image: bytes


def parse_bundle(data: bytes) -> list[Record]:
    if data[:8] != MAGIC or len(data) < 12:
        raise ValueError("invalid bundle header")
    count = struct.unpack_from("<I", data, 8)[0]
    cursor = 12
    records = []
    for index in range(count):
        if cursor + 44 > len(data):
            raise ValueError(f"truncated record {index}")
        kind, tier, anchors, reserved, pattern_len, image_len = struct.unpack_from(
            "<BBBBII", data, cursor
        )
        cursor += 12
        class_bits = data[cursor : cursor + 32]
        cursor += 32
        end_pattern = cursor + pattern_len
        end_image = end_pattern + image_len
        if (
            reserved != 0
            or kind > 1
            or tier > 2
            or anchors & ~3
            or end_image > len(data)
        ):
            raise ValueError(f"invalid record {index}")
        records.append(
            Record(
                kind,
                tier,
                anchors,
                class_bits,
                data[cursor:end_pattern],
                data[end_pattern:end_image],
            )
        )
        cursor = end_image
    if cursor != len(data):
        raise ValueError("trailing bundle bytes")
    return records


def member(record: Record, byte: int) -> bool:
    return bool(record.class_bits[byte >> 3] & (1 << (byte & 7)))


def matches_at(haystack: bytes, end: int, at: int, pattern: bytes) -> bool:
    return at <= end and len(pattern) <= end - at and haystack[at : at + len(pattern)] == pattern


def reference_exact(record: Record, haystack: bytes, start: int, end: int) -> tuple[int, int, int]:
    length = len(haystack)
    if start > end or end > length:
        return (2, 0, 0)
    anchored_start = bool(record.anchors & 1)
    anchored_end = bool(record.anchors & 2)
    pattern = record.pattern
    if anchored_start:
        if start == 0 and matches_at(haystack, end, 0, pattern) and (
            not anchored_end or len(pattern) == length
        ):
            return (1, 0, len(pattern))
        return (0, 0, 0)
    if anchored_end:
        if len(pattern) <= length:
            candidate = length - len(pattern)
            if candidate >= start and matches_at(haystack, end, candidate, pattern):
                return (1, candidate, length)
        return (0, 0, 0)
    for at in range(start, end + 1):
        if matches_at(haystack, end, at, pattern):
            return (1, at, at + len(pattern))
    return (0, 0, 0)


def reference_class(record: Record, haystack: bytes, start: int, end: int) -> tuple[int, int, int]:
    length = len(haystack)
    if start > end or end > length:
        return (2, 0, 0)
    anchored_start = bool(record.anchors & 1)
    anchored_end = bool(record.anchors & 2)
    cursor = start
    while True:
        run_start = cursor
        if anchored_start:
            if cursor != 0 or cursor == end or not member(record, haystack[cursor]):
                return (0, 0, 0)
        else:
            while run_start < end and not member(record, haystack[run_start]):
                run_start += 1
            if run_start == end:
                return (0, 0, 0)
        run_end = run_start + 1
        while run_end < end and member(record, haystack[run_end]):
            run_end += 1
        if matches_at(haystack, end, run_end, record.pattern):
            match_end = run_end + len(record.pattern)
            if not anchored_end or match_end == length:
                return (1, run_start, match_end)
        cursor = run_end


def reference(record: Record, haystack: bytes, start: int, end: int) -> tuple[int, int, int]:
    if record.kind == 0:
        return reference_exact(record, haystack, start, end)
    return reference_class(record, haystack, start, end)


class Machine:
    def __init__(self, record: Record) -> None:
        self.record = record
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        code_size = (len(record.image) + PAGE - 1) & ~(PAGE - 1)
        self.uc.mem_map(CODE, max(code_size, PAGE))
        self.uc.mem_write(CODE, record.image)
        self.uc.mem_map(HAYSTACK, 0x20_000)
        self.uc.mem_map(RESULT, PAGE)
        self.uc.mem_map(STACK, PAGE)

    def run(self, haystack: bytes, start: int, end: int) -> tuple[int, int, int]:
        self.uc.mem_write(HAYSTACK, haystack or b"\0")
        self.uc.mem_write(RESULT, b"\xff" * 16)
        stack_pointer = STACK + PAGE // 2
        self.uc.mem_write(stack_pointer, struct.pack("<Q", STOP))
        self.uc.reg_write(UC_X86_REG_RDI, HAYSTACK)
        self.uc.reg_write(UC_X86_REG_RSI, len(haystack))
        self.uc.reg_write(UC_X86_REG_RDX, start)
        self.uc.reg_write(UC_X86_REG_RCX, end)
        self.uc.reg_write(UC_X86_REG_R8, RESULT)
        self.uc.reg_write(UC_X86_REG_RSP, stack_pointer)
        self.uc.reg_write(UC_X86_REG_RFLAGS, 2)
        self.uc.reg_write(UC_X86_REG_RAX, 0xA0_A0_A0_A0_A0_A0_A0_A0)
        self.uc.reg_write(UC_X86_REG_R9, 0xA9_A9_A9_A9_A9_A9_A9_A9)
        self.uc.reg_write(UC_X86_REG_R10, 0xAA_AA_AA_AA_AA_AA_AA_AA)
        self.uc.reg_write(UC_X86_REG_R11, 0xAB_AB_AB_AB_AB_AB_AB_AB)
        budget = (len(haystack) + 1) * (len(self.record.pattern) + 64) * 32 + 2_000
        self.uc.emu_start(CODE, STOP, count=budget)
        if self.uc.reg_read(UC_X86_REG_RIP) != STOP:
            raise RuntimeError("native entry exceeded its instruction budget")
        status = self.uc.reg_read(UC_X86_REG_RAX) & 0xFFFF_FFFF
        match_start, match_end = struct.unpack("<QQ", self.uc.mem_read(RESULT, 16))
        return (status, match_start, match_end)


def cases(record: Record):
    alphabet = b"abXY"
    for length in range(4):
        for symbols in itertools.product(alphabet, repeat=length):
            haystack = bytes(symbols)
            for start in range(length + 1):
                for end in range(start, length + 1):
                    yield haystack, start, end
            yield haystack, length + 1, length
            yield haystack, 0, length + 1

    core = record.pattern
    if record.kind == 1:
        first = next(byte for byte in range(256) if member(record, byte))
        core = bytes([first]) * 3 + core
    prefix = b"" if record.anchors & 1 else b"\xee"
    suffix = b"" if record.anchors & 2 else b"\xee"
    targeted = prefix + core + suffix
    yield targeted, 0, len(targeted)
    if record.pattern:
        mutated = bytearray(targeted)
        pattern_end = len(prefix) + len(core)
        mutated[pattern_end - 1] ^= 0x5A
        yield bytes(mutated), 0, len(mutated)
    if record.anchors == 0:
        long_haystack = bytearray(b"\xee" * 4096)
        at = 2000
        if record.kind == 1:
            first = next(byte for byte in range(256) if member(record, byte))
            long_haystack[at : at + 7] = bytes([first]) * 7
            at += 7
        long_haystack[at : at + len(record.pattern)] = record.pattern
        yield bytes(long_haystack), 0, len(long_haystack)


def qualify(records: list[Record]) -> tuple[int, int]:
    comparisons = 0
    skipped = 0
    for index, record in enumerate(records):
        try:
            machine = Machine(record)
            for haystack, start, end in cases(record):
                expected = reference(record, haystack, start, end)
                actual = machine.run(haystack, start, end)
                comparisons += 1
                if actual != expected:
                    raise AssertionError(
                        f"record={index} kind={record.kind} tier={record.tier} "
                        f"anchors={record.anchors} pattern={record.pattern.hex()} "
                        f"window={start}..{end} haystack={haystack.hex()} "
                        f"expected={expected} actual={actual}"
                    )
        except UcError as error:
            if record.tier == 2 and "UC_ERR_INSN_INVALID" in str(error):
                skipped += 1
                continue
            raise RuntimeError(f"Unicorn record={index}: {error}") from error
    return comparisons, skipped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    arguments = parser.parse_args()
    with open(arguments.bundle, "rb") as bundle_file:
        records = parse_bundle(bundle_file.read())
    comparisons, skipped = qualify(records)
    print(
        f"records={len(records)} executed={len(records) - skipped} "
        f"skipped={skipped} comparisons={comparisons}"
    )


if __name__ == "__main__":
    main()
