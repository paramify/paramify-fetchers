"""Read the facts off an ASCII-armored OpenPGP public key (RFC 4880 v4 packets), stdlib only. Nothing is verified."""

import base64
import binascii
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

ARMOR = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n(?P<body>.*?)-----END PGP PUBLIC KEY BLOCK-----", re.DOTALL
)
EMAIL = re.compile(r"[^\s<>()\"']+@[^\s<>()\"']+\.[A-Za-z0-9-]+")

TAG_SIGNATURE, TAG_PUBLIC_KEY, TAG_USER_ID, TAG_PUBLIC_SUBKEY = 2, 6, 13, 14
CERTIFICATIONS = {0x10, 0x11, 0x12, 0x13}
SUBKEY_BINDING, DIRECT_KEY, KEY_REVOCATION, SUBKEY_REVOCATION = 0x18, 0x1F, 0x20, 0x28
SUB_CREATED, SUB_KEY_EXPIRES, SUB_ISSUER, SUB_KEY_FLAGS, SUB_ISSUER_FPR = 2, 9, 16, 27, 33
ALGORITHMS = {1: "RSA", 2: "RSA (encrypt only)", 3: "RSA (sign only)", 16: "Elgamal", 17: "DSA",
              18: "ECDH", 19: "ECDSA", 22: "EdDSA", 25: "X25519", 27: "Ed25519"}
FLAGS = {0x01: "certify", 0x02: "sign", 0x04: "encrypt_communications", 0x08: "encrypt_storage",
         0x20: "authenticate"}


class KeyParseError(ValueError):
    pass


def find_armored_key(text: str) -> Optional[str]:
    match = ARMOR.search(text)
    return match.group(0) if match else None


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(armored: str) -> bytes:
    match = ARMOR.search(armored)
    if not match:
        raise KeyParseError("no ASCII-armored public key block")
    lines = match.group("body").replace("\r", "").split("\n")
    if "" in lines:  # armor headers end at the first blank line
        lines = lines[lines.index("") + 1:]
    checksum = next((line[1:] for line in lines if line.startswith("=")), None)
    data = "".join(line.strip() for line in lines if line.strip() and not line.startswith("="))
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyParseError(f"armor is not valid base64: {exc}") from exc
    if checksum is not None:
        try:
            expected = int.from_bytes(base64.b64decode(checksum, validate=True), "big")
        except (binascii.Error, ValueError) as exc:
            raise KeyParseError(f"armor checksum is not valid base64: {exc}") from exc
        if _crc24(raw) != expected:
            raise KeyParseError("armor CRC24 checksum does not match the key data")
    return raw


def packets(data: bytes) -> List[Tuple[int, bytes]]:
    out, i = [], 0
    while i < len(data):
        header = data[i]
        if not header & 0x80:
            raise KeyParseError(f"byte {i} is not a packet header")
        if header & 0x40:  # new format
            tag, i = header & 0x3F, i + 1
            first = data[i]
            if first < 192:
                length, i = first, i + 1
            elif first < 224:
                length, i = ((first - 192) << 8) + data[i + 1] + 192, i + 2
            elif first == 255:
                length, i = int.from_bytes(data[i + 1:i + 5], "big"), i + 5
            else:
                raise KeyParseError("partial body lengths are not used in keys")
        else:  # old format
            tag, kind, i = (header >> 2) & 0x0F, header & 0x03, i + 1
            if kind == 3:
                raise KeyParseError("indeterminate packet length")
            size = 1 << kind
            length, i = int.from_bytes(data[i:i + size], "big"), i + size
        if i + length > len(data):
            raise KeyParseError("packet runs past the end of the key data")
        out.append((tag, data[i:i + length]))
        i += length
    return out


def _iso(epoch: Optional[int]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_key(body: bytes) -> Dict[str, Any]:
    if not body or body[0] != 4:
        raise KeyParseError(f"public key packet version {body[0] if body else '?'} (only v4 is read)")
    created = int.from_bytes(body[1:5], "big")
    # RFC 4880 §12.2 defines v4 fingerprints as SHA-1; an identifier, not a verification.
    fingerprint = hashlib.sha1(
        b"\x99" + len(body).to_bytes(2, "big") + body, usedforsecurity=False
    ).hexdigest().upper()
    algorithm = body[5]
    bits = None
    if algorithm in (1, 2, 3):
        bits = int.from_bytes(body[6:8], "big")
    return {"fingerprint": fingerprint, "key_id": fingerprint[-16:], "created_epoch": created,
            "algorithm": ALGORITHMS.get(algorithm, f"algorithm {algorithm}"), "bits": bits}


def _subpackets(data: bytes) -> List[Tuple[int, bytes]]:
    out, i = [], 0
    while i < len(data):
        first = data[i]
        if first < 192:
            length, i = first, i + 1
        elif first < 255:
            length, i = ((first - 192) << 8) + data[i + 1] + 192, i + 2
        else:
            length, i = int.from_bytes(data[i + 1:i + 5], "big"), i + 5
        if length == 0 or i + length > len(data):
            raise KeyParseError("malformed signature subpacket")
        out.append((data[i] & 0x7F, data[i + 1:i + length]))
        i += length
    return out


def _signature(body: bytes) -> Optional[Dict[str, Any]]:
    if not body or body[0] != 4:
        return None  # v3 signatures carry no subpackets; not read
    sig_type = body[1]
    hashed_len = int.from_bytes(body[4:6], "big")
    hashed = body[6:6 + hashed_len]
    rest = body[6 + hashed_len:]
    unhashed = rest[2:2 + int.from_bytes(rest[0:2], "big")]
    sig: Dict[str, Any] = {"type": sig_type, "created": None, "key_expires_after": None, "issuer": None, "flags": None}
    for source, block in (("hashed", hashed), ("unhashed", unhashed)):
        for kind, value in _subpackets(block):
            if source == "hashed" and kind == SUB_CREATED:
                sig["created"] = int.from_bytes(value, "big")
            elif source == "hashed" and kind == SUB_KEY_EXPIRES:
                sig["key_expires_after"] = int.from_bytes(value, "big")
            elif source == "hashed" and kind == SUB_KEY_FLAGS and value:
                sig["flags"] = value[0]
            elif kind == SUB_ISSUER_FPR and len(value) > 1:
                sig["issuer"] = value[1:].hex().upper()[-16:]
            elif kind == SUB_ISSUER and sig["issuer"] is None:
                sig["issuer"] = value.hex().upper()
    return sig


def _expiry(created: int, sigs: List[Dict[str, Any]]) -> Optional[int]:
    """From the newest self-signature that says anything; 0 or absent means no expiry."""
    dated = [s for s in sigs if s["created"] is not None]
    if not dated:
        return None
    after = max(dated, key=lambda s: s["created"])["key_expires_after"]
    return created + after if after else None


def _flags(sigs: List[Dict[str, Any]]) -> Optional[List[str]]:
    dated = [s for s in sigs if s["flags"] is not None]
    if not dated:
        return None
    value = max(dated, key=lambda s: s["created"] or 0)["flags"]
    return [name for bit, name in FLAGS.items() if value & bit]


def parse_public_key(armored: str) -> Dict[str, Any]:
    """Fingerprint, creation, expiry, user IDs and subkeys of the first primary key. Raises KeyParseError."""
    stream = packets(dearmor(armored))
    if not stream or stream[0][0] != TAG_PUBLIC_KEY:
        raise KeyParseError("the key data does not start with a public-key packet")
    primary = _public_key(stream[0][1])
    key_id = primary["key_id"]
    user_ids: List[str] = []
    primary_sigs: List[Dict[str, Any]] = []
    subkeys: List[Dict[str, Any]] = []
    revoked = False
    context = "primary"
    for tag, body in stream[1:]:
        if tag == TAG_PUBLIC_KEY:
            break  # a second certificate in the same block; only the first is read
        if tag == TAG_USER_ID:
            user_ids.append(body.decode("utf-8", errors="replace"))
            context = "uid"
        elif tag == TAG_PUBLIC_SUBKEY:
            subkeys.append({**_public_key(body), "sigs": [], "revoked": False})
            context = "subkey"
        elif tag == TAG_SIGNATURE:
            sig = _signature(body)
            if sig is None or (sig["issuer"] and sig["issuer"] != key_id):
                continue  # not a self-signature
            if sig["type"] == KEY_REVOCATION:
                revoked = True
            elif context == "subkey" and sig["type"] == SUBKEY_REVOCATION:
                subkeys[-1]["revoked"] = True
            elif context == "subkey" and sig["type"] == SUBKEY_BINDING:
                subkeys[-1]["sigs"].append(sig)
            elif sig["type"] in CERTIFICATIONS or sig["type"] == DIRECT_KEY:
                primary_sigs.append(sig)

    created = primary["created_epoch"]
    return {
        "fingerprint": primary["fingerprint"],
        "key_id": key_id,
        "algorithm": primary["algorithm"],
        "bits": primary["bits"],
        "created": _iso(created),
        "expires": _iso(_expiry(created, primary_sigs)),
        "revoked": revoked,
        "flags": _flags(primary_sigs),
        "user_ids": user_ids,
        "emails": sorted({m.group(0).lower() for uid in user_ids for m in EMAIL.finditer(uid)}),
        "subkeys": [
            {
                "fingerprint": sub["fingerprint"],
                "algorithm": sub["algorithm"],
                "bits": sub["bits"],
                "created": _iso(sub["created_epoch"]),
                "expires": _iso(_expiry(sub["created_epoch"], sub["sigs"])),
                "revoked": sub["revoked"],
                "flags": _flags(sub["sigs"]),
            }
            for sub in subkeys
        ],
    }


def encryption_usable_until(key: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """(has a usable encryption key, until when; None = no expiry), from parse_public_key() output."""
    if key["revoked"]:
        return False, None
    candidates = [s for s in key["subkeys"] if not s["revoked"] and any("encrypt" in f for f in s["flags"] or [])]
    if any("encrypt" in f for f in key["flags"] or []):
        candidates.append(key)
    if not candidates:
        return False, None
    ends = [c["expires"] for c in candidates]
    latest = None if None in ends else max(ends)  # ISO-8601 Z strings sort chronologically
    if key["expires"] is not None and (latest is None or key["expires"] < latest):
        latest = key["expires"]
    return True, latest
