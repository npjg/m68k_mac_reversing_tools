"""Big-endian integer reading and writing for M68k Mac resources."""

from io import BytesIO

from mrcrowbar import utils

# Conversions between big-endian bytes and Python integers.
u16 = utils.from_uint16_be
i16 = utils.from_int16_be
u32 = utils.from_uint32_be

to_u16 = utils.to_uint16_be
to_u32 = utils.to_uint32_be


def read_u16(stream: BytesIO) -> int:
    return u16(stream.read(2))


def read_u32(stream: BytesIO) -> int:
    return u32(stream.read(4))


def write_u16(stream: BytesIO, value: int) -> None:
    stream.write(to_u16(value))


def write_u32(stream: BytesIO, value: int) -> None:
    stream.write(to_u32(value))


def write_i16_as_u16(stream: BytesIO, value: int) -> None:
    """Write a signed 16-bit value using its two's-complement unsigned encoding."""
    stream.write(to_u16(value & 0xFFFF))
