#!/usr/bin/env python3
"""
Convert a WinSCP configuration file (WinSCP.ini) into a FileZilla
Site Manager file (sitemanager.xml).

Python port of https://github.com/Mikaciu/WinSCPSiteConfigurationToFileZilla
(index.php + WinSCPPasswordDecrypt.jar). The password decryption that the
original shelled out to Java for is implemented here directly, so only the
Python 3.9+ standard library is needed.

Usage:
    python winscp_to_filezilla.py WinSCP.ini                 # writes ./sitemanager.xml
    python winscp_to_filezilla.py WinSCP.ini -o out.xml
    python winscp_to_filezilla.py WinSCP.ini -o -            # write to stdout
"""

import argparse
import base64
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import unquote

# WinSCP's "simple" password obfuscation constants
PWALG_SIMPLE_MAGIC = 0xA3
PWALG_SIMPLE_FLAG = 0xFF

SECTION_RE = re.compile(r"^\[(.*)\]\s*$")
SESSION_PREFIX = "Sessions\\"


# --------------------------------------------------------------------------
# Password decryption (replaces WinSCPPasswordDecrypt.jar)
# --------------------------------------------------------------------------

def decrypt_password(hostname: str, username: str, encrypted: str) -> str:
    """Decode a password stored by WinSCP (without a master password).

    Returns an empty string if the value is missing or can't be decoded.
    """
    if not encrypted:
        return ""
    try:
        nibbles = [int(c, 16) for c in encrypted]
    except ValueError:
        return ""
    pos = 0

    def next_char() -> int:
        nonlocal pos
        if pos + 1 >= len(nibbles):
            raise ValueError("ran out of data")
        value = (nibbles[pos] << 4) + nibbles[pos + 1]
        pos += 2
        return ~(value ^ PWALG_SIMPLE_MAGIC) & 0xFF

    try:
        flag = next_char()
        if flag == PWALG_SIMPLE_FLAG:
            next_char()                # internal marker byte, unused
            length = next_char()
        else:
            length = flag
        shift = next_char()
        pos += shift * 2               # skip the random padding
        result = "".join(chr(next_char()) for _ in range(length))
    except ValueError:
        return ""

    if flag == PWALG_SIMPLE_FLAG:
        key = username + hostname
        if not result.startswith(key):
            return ""
        result = result[len(key):]
    return result


# --------------------------------------------------------------------------
# INI reading
# --------------------------------------------------------------------------

def read_text(path: str) -> str:
    with open(path, "rb") as fh:
        raw = fh.read()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def read_sessions(path: str) -> dict:
    """Return {session_path: {key: value}} for every [Sessions\\...] section."""
    sessions = {}
    current = None
    for line in read_text(path).splitlines():
        stripped = line.strip()
        match = SECTION_RE.match(stripped)
        if match:
            name = match.group(1)
            if name.startswith(SESSION_PREFIX):
                current = sessions.setdefault(name[len(SESSION_PREFIX):], {})
            else:
                current = None
            continue
        if current is None or not stripped or stripped.startswith(";"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip()
    return sessions


# --------------------------------------------------------------------------
# FileZilla XML building
# --------------------------------------------------------------------------

def sub(parent: ET.Element, tag: str, text=None, **attrs) -> ET.Element:
    el = ET.SubElement(parent, tag, attrs)
    if text is not None:
        el.text = str(text)
    return el


def remote_dir_to_filezilla(path: str) -> str:
    """'/var/www' -> '1 0 3 var 3 www' (FileZilla's serialized path format)."""
    out = "1"
    for part in path.split("/"):
        out += f" {len(part)}"
        if part:
            out += f" {part}"
    return out


def build_server(label: str, conf: dict) -> ET.Element:
    host = conf["HostName"]
    user = conf.get("UserName", "")

    # Protocol 0 = FTP, 1 = SFTP. WinSCP's FSProtocol 5 is FTP; anything else
    # (or absent, which WinSCP uses for its SFTP default) maps to SFTP.
    is_ftp = conf.get("FSProtocol") == "5"

    server = ET.Element("Server")
    sub(server, "Host", host)
    sub(server, "Protocol", 0 if is_ftp else 1)
    sub(server, "User", user)

    password = decrypt_password(host, user, conf.get("Password", ""))
    sub(server, "Pass", base64.b64encode(password.encode("utf-8")).decode("ascii"),
        encoding="base64")

    sub(server, "LocalDir", unquote(conf.get("LocalDirectory", "")))

    logon_type = 1  # normal (user + password)
    if "PublicKeyFile" in conf:
        sub(server, "Keyfile", unquote(conf["PublicKeyFile"]))
        logon_type = 5  # key file
    else:
        sub(server, "Keyfile", "")

    if "RemoteDirectory" in conf:
        sub(server, "RemoteDir", remote_dir_to_filezilla(unquote(conf["RemoteDirectory"])))
    else:
        sub(server, "RemoteDir", "")

    # WinSCP omits PortNumber when it's the protocol default
    sub(server, "Port", conf.get("PortNumber", 21 if is_ftp else 22))
    sub(server, "Type", 0)
    sub(server, "Logontype", logon_type)
    sub(server, "TimezoneOffset", 0)
    sub(server, "PasvMode", "MODE_DEFAULT")
    sub(server, "MaximumMultipleConnections", 0)
    sub(server, "EncodingType", "Auto")
    sub(server, "BypassProxy", 0)
    sub(server, "SyncBrowsing", 0)
    sub(server, "Comments")
    sub(server, "Name", label)
    return server


def convert(ini_path: str) -> ET.ElementTree:
    sessions = read_sessions(ini_path)
    if not sessions:
        raise ValueError("The attempt to read the .ini file failed (no sessions found).")

    root = ET.Element("FileZilla3")
    servers = ET.SubElement(root, "Servers")

    # Nested folder tree: {"folders": {name: node}, "sites": [Server elements]}
    tree = {"folders": {}, "sites": []}

    for session_path in sorted(sessions):
        conf = sessions[session_path]
        if "HostName" not in conf:
            continue  # same as the original: skip entries without a host

        *folders, label = session_path.split("/")
        node = tree
        for folder in folders:
            node = node["folders"].setdefault(unquote(folder), {"folders": {}, "sites": []})
        node["sites"].append(build_server(unquote(label), conf))

    def emit(node: dict, parent: ET.Element) -> None:
        # Sessions were sorted by full path, so folders and sites keep
        # WinSCP's alphabetical order.
        for name, child in node["folders"].items():
            folder_el = sub(parent, "Folder", name)
            emit(child, folder_el)
        for site in node["sites"]:
            parent.append(site)

    emit(tree, servers)
    return ET.ElementTree(root)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert WinSCP.ini sessions to a FileZilla sitemanager.xml")
    parser.add_argument("ini", help="path to WinSCP.ini")
    parser.add_argument("-o", "--output", default="sitemanager.xml",
                        help="output file (default: sitemanager.xml, '-' for stdout)")
    args = parser.parse_args()

    try:
        tree = convert(args.ini)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    ET.indent(tree, space="  ")
    xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           + ET.tostring(tree.getroot(), encoding="unicode") + "\n")

    if args.output == "-":
        sys.stdout.write(xml)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(xml)
        count = len(tree.getroot().findall(".//Server"))
        print(f"Wrote {count} site(s) to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
