#!/usr/bin/env python3
"""Reading classic Mac OS resource forks, and reinterpreting the big-endian scalars within them."""
from __future__ import annotations

import collections
import os

import machfs
import macresources
from mrcrowbar.lib.containers import mac

# A resource fork indexed first by four-character resource type (e.g. b"CODE") and then by resource id.
ResourceFork = dict[bytes, dict[int, macresources.main.Resource]]


def get_code_resource_label(resource_id: int, resource: macresources.main.Resource) -> str:
    """Build a human-readable label for a CODE resource, appending its name when it has one."""
    if resource.name is None:
        return str(resource_id)

    if isinstance(resource.name, bytes):
        resource_name = resource.name.decode("ascii", errors="replace")
    else:
        resource_name = str(resource.name)

    return f"{resource_id} ({resource_name})"


# Reinterpret an unsigned N-bit value as a two's-complement signed value. C++ obtained the same
# effect through fixed-width signed integer casts (int8_t/int16_t/int32_t).
def as_int8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value

def as_int16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value

def as_int32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def get_file_from_volume(image_filepath: str, path_in_volume: list[str] | None) -> tuple[bytes, ResourceFork]:
    resources: ResourceFork = collections.defaultdict(dict)

    with open(image_filepath, "rb") as f:
        flat = f.read()
        volume = machfs.Volume()
        volume.read(flat)
        print(volume)
        if not path_in_volume:
            raise ValueError("HFS volume was provided without path!")
        for path_component in path_in_volume:
            volume = volume[path_component]
        for resource in macresources.parse_file(volume.rsrc):
            resources[resource.type][resource.id] = resource

        return volume.data, resources


def get_file_from_macbinary(filepath: str) -> tuple[bytes, ResourceFork]:
    file_contents = open(filepath, "rb").read()
    macbinary = mac.MacBinary(file_contents)
    resources: ResourceFork = collections.defaultdict(dict)
    for resource in macresources.parse_file(macbinary.resource):
        resources[resource.type][resource.id] = resource

    return macbinary.data, resources


def read_resource_fork(source_filepath: str, path_in_volume: list[str] | None) -> ResourceFork:
    """Read the resource fork from an HFS disk image or a MacBinary file, auto-detecting which."""
    with open(source_filepath, "rb") as source_file:
        source_file.seek(122, os.SEEK_SET)
        is_likely_macbinary = (int.from_bytes(source_file.read(2), "big") & 0xFCFF) == 0x8081

        source_file.seek(0x400, os.SEEK_SET)
        volume_signature = source_file.read(2)

    is_likely_hfs_volume = volume_signature in (b"BD", b"H+")
    if is_likely_hfs_volume:
        _, resources = get_file_from_volume(source_filepath, path_in_volume)
    elif is_likely_macbinary:
        _, resources = get_file_from_macbinary(source_filepath)
    else:
        raise ValueError(f"File {source_filepath} must be a HFS disk image or MacBinary file")

    show_all_resource_types(resources)
    return resources

def show_all_resource_types(resources: ResourceFork):
    # For debugging purposes, print all the resources we found.
    for resource_type in resources:
        print(resource_type)
        for j, r in resources[resource_type].items():
            if r.name != None:
                print(f"    {j}: {r.name}")
            else:
                print(f"    {j}")
