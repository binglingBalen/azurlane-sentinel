"""Content protocol shared by cloud sentinel and local successful asset snapshot."""
import hashlib
import json


def content_signature(manifest, names):
    # Exactly alz.hotupdate.check's existing content signature, including the
    # complete az manifest and every independent manifest advertised by login.
    return hashlib.sha256(json.dumps([sorted(manifest.items()), names],
        separators=(',', ':')).encode('utf-8')).hexdigest()


def parse_manifest(data):
    entries = {}
    for line in data.decode('utf-8-sig').splitlines():
        if not line.strip():
            continue
        path, size, md5 = line.strip().split(',')
        if path in entries or int(size) < 0 or len(md5) != 32 or any(c not in '0123456789abcdefABCDEF' for c in md5):
            raise ValueError('Invalid or duplicate manifest entry: ' + path)
        entries[path] = (int(size), md5)
    if not entries:
        raise ValueError('Empty online manifest')
    return entries


def snapshot_signature(snapshot):
    sources = snapshot.get('sources') or {}
    paths = snapshot.get('az_paths')
    if not sources or not paths:
        return None
    entries = {p:snapshot['assets'][p] for p in paths}
    return content_signature(entries, list(sources.values()))
