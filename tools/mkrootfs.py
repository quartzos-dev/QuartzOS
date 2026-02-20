#!/usr/bin/env python3
import argparse
import os
import struct

SFS_MAGIC = 0x31534653
SFS_VERSION = 1
SFS_TYPE_DIR = 1
SFS_TYPE_FILE = 2
SFS_MAX_NAME = 56
SFS_ROOT_PARENT = 0xFFFFFFFF

HEADER_FMT = "<IIIIII"
ENTRY_FMT = "<56sIIIII"


class Builder:
    def __init__(self):
        self.entries = []
        self.path_to_index = {}
        self.file_payloads = {}
        self.add_dir("/")

    def norm(self, path):
        if not path.startswith("/"):
            path = "/" + path
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        return path

    def split_parent(self, path):
        path = self.norm(path)
        if path == "/":
            return "/", ""
        parent = os.path.dirname(path)
        if not parent:
            parent = "/"
        return parent, os.path.basename(path)

    def add_dir(self, path):
        path = self.norm(path)
        if path in self.path_to_index:
            return self.path_to_index[path]
        if path == "/":
            idx = len(self.entries)
            self.entries.append({
                "name": "/",
                "parent": SFS_ROOT_PARENT,
                "type": SFS_TYPE_DIR,
                "offset": 0,
                "size": 0,
            })
            self.path_to_index[path] = idx
            return idx

        parent, name = self.split_parent(path)
        parent_idx = self.add_dir(parent)
        idx = len(self.entries)
        self.entries.append({
            "name": name,
            "parent": parent_idx,
            "type": SFS_TYPE_DIR,
            "offset": 0,
            "size": 0,
        })
        self.path_to_index[path] = idx
        return idx

    def add_file(self, path, data):
        path = self.norm(path)
        parent, name = self.split_parent(path)
        parent_idx = self.add_dir(parent)

        idx = len(self.entries)
        self.entries.append({
            "name": name,
            "parent": parent_idx,
            "type": SFS_TYPE_FILE,
            "offset": 0,
            "size": len(data),
        })
        self.path_to_index[path] = idx
        self.file_payloads[idx] = data

    def serialize(self):
        entry_count = len(self.entries)
        header_size = struct.calcsize(HEADER_FMT)
        entry_size = struct.calcsize(ENTRY_FMT)
        entries_offset = header_size
        data_offset = entries_offset + entry_count * entry_size

        data_cursor = data_offset
        blob = bytearray()
        for idx, ent in enumerate(self.entries):
            if ent["type"] == SFS_TYPE_FILE:
                ent["offset"] = data_cursor
                data_cursor += ent["size"]

        image_size = data_cursor

        blob += struct.pack(
            HEADER_FMT,
            SFS_MAGIC,
            SFS_VERSION,
            entry_count,
            entries_offset,
            data_offset,
            image_size,
        )

        for ent in self.entries:
            name = ent["name"].encode("utf-8")[: SFS_MAX_NAME - 1]
            name = name + b"\x00" * (SFS_MAX_NAME - len(name))
            blob += struct.pack(
                ENTRY_FMT,
                name,
                ent["parent"],
                ent["type"],
                ent["offset"],
                ent["size"],
                0,
            )

        for idx in range(len(self.entries)):
            if idx in self.file_payloads:
                blob += self.file_payloads[idx]

        return bytes(blob)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument(
        "--add",
        action="append",
        default=[],
        help="mapping virtual_path=host_file",
    )
    parser.add_argument(
        "--add-tree",
        action="append",
        default=[],
        help="mapping virtual_dir=host_dir (recursive)",
    )
    args = parser.parse_args()

    b = Builder()
    b.add_dir("/bin")
    b.add_dir("/home")
    b.add_file("/readme.txt", b"QuartzOS root filesystem\\n")

    for mapping in args.add:
        if "=" not in mapping:
            raise SystemExit(f"invalid --add mapping: {mapping}")
        virt, host = mapping.split("=", 1)
        with open(host, "rb") as f:
            data = f.read()
        b.add_file(virt, data)

    for mapping in args.add_tree:
        if "=" not in mapping:
            raise SystemExit(f"invalid --add-tree mapping: {mapping}")
        virt_root, host_root = mapping.split("=", 1)
        if not os.path.isdir(host_root):
            raise SystemExit(f"--add-tree host path is not a directory: {host_root}")

        virt_root = b.norm(virt_root)
        for root, dirs, files in os.walk(host_root):
            dirs.sort()
            files.sort()
            rel_dir = os.path.relpath(root, host_root)
            if rel_dir == ".":
                rel_dir = ""

            for name in files:
                host_file = os.path.join(root, name)
                rel_path = os.path.join(rel_dir, name).replace(os.sep, "/")
                virt_path = virt_root + "/" + rel_path if rel_path else virt_root
                with open(host_file, "rb") as f:
                    data = f.read()
                b.add_file(virt_path, data)

    image = b.serialize()
    with open(args.output, "wb") as f:
        f.write(image)


if __name__ == "__main__":
    main()
