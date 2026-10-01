"""Post-quantum (X25519MLKEM768) key exchange for aioquic - pure Python.

The official WARP client enables post-quantum MASQUE, and its ClientHello
carries a 1216-byte X25519MLKEM768 key share (tcpdump on a working client shows
two 1200-byte Initial packets).  Padding our ClientHello to the same size is not
enough - the exchange itself has to be post-quantum.

aioquic's TLS only knows X25519/P-xxx, so this module installs a small shim:

* ``tls.x25519.X25519PrivateKey`` is replaced by a hybrid private key that also
  owns an ML-KEM-768 key pair,
* ``push_client_hello`` gains the ``(0x11EC, mlkem_pub || x25519_pub)`` share,
* ``decode_public_key`` splits the server's ``(mlkem_ct || x25519_pub)`` answer
  and hands the existing dispatch a plain X25519 public key, while stashing the
  ML-KEM ciphertext for the hybrid ``exchange()``.

The result is a 64-byte secret (ML-KEM secret || X25519 secret) exactly as
draft-ietf-tls-ecdhe-mlkem specifies.

``cryptography >= 45`` provides ML-KEM; nothing else is needed.
"""

from __future__ import annotations

import logging
import os

import aioquic.tls as tls
from cryptography.hazmat.primitives.asymmetric import x25519 as real_x25519

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
except ImportError:  # this cryptography build has no ML-KEM module
    mlkem = None  # type: ignore[assignment]

log = logging.getLogger("waygate.pq")

#: codepoint of the hybrid X25519MLKEM768 group (draft-ietf-tls-ecdhe-mlkem)
GROUP_X25519MLKEM768 = 0x11EC
#: older draft code point Cloudflare's BoringSSL also implements
GROUP_X25519KYBER768DRAFT00 = 0x6399


def _group_id() -> int:
    """Which hybrid group code point to offer (overridable for experiments)."""
    raw = os.environ.get("WAYGATE_PQ_GROUP") or os.environ.get("WARP2S5_PQ_GROUP") or ""
    try:
        return int(raw, 16) if raw else GROUP_X25519MLKEM768
    except ValueError:
        return GROUP_X25519MLKEM768


MLKEM768_CIPHERTEXT_SIZE = 1088
MLKEM768_PUBLIC_KEY_SIZE = 1184

#: ML-KEM ciphertexts from the ServerHello, keyed by the X25519 public key we
#: hand back to aioquic (consumed immediately by ``exchange``)
_PEER_CIPHERTEXTS: dict[int, bytes] = {}
#: the hybrid key pair generated for the ClientHello currently being built
_PENDING: list["_HybridPrivateKey"] = []
_APPLIED = False


class _HybridPrivateKey:
    """Looks like an X25519 private key, but exchanges X25519MLKEM768."""

    def __init__(self) -> None:
        self._x25519 = real_x25519.X25519PrivateKey.generate()
        self._mlkem = mlkem.MLKEM768PrivateKey.generate()
        mlkem_public = self._mlkem.public_key().public_bytes_raw()
        assert len(mlkem_public) == MLKEM768_PUBLIC_KEY_SIZE
        self.key_share_payload = mlkem_public + self._x25519.public_key().public_bytes_raw()

    # aioquic calls this to build the (plain X25519) key share entry
    def public_key(self) -> real_x25519.X25519PublicKey:
        return self._x25519.public_key()

    # aioquic calls this to derive the handshake secret
    def exchange(self, peer_public_key) -> bytes:  # type: ignore[no-untyped-def]
        ciphertext = _PEER_CIPHERTEXTS.pop(id(peer_public_key), None)
        if ciphertext is None:
            return self._x25519.exchange(peer_public_key)
        mlkem_secret = self._mlkem.decapsulate(ciphertext)
        x25519_secret = self._x25519.exchange(peer_public_key)
        log.debug("X25519MLKEM768 exchange: %d + %d bytes",
                  len(mlkem_secret), len(x25519_secret))
        return mlkem_secret + x25519_secret


class _X25519Shim:
    """Stands in for aioquic.tls's ``x25519`` module."""

    X25519PrivateKey = _HybridPrivateKey
    X25519PublicKey = real_x25519.X25519PublicKey


def enable_post_quantum() -> bool:
    """Install the hybrid key exchange. Returns False if it is not available."""
    global _APPLIED
    if _APPLIED:
        return True
    if os.environ.get("WAYGATE_NO_PQ") or os.environ.get("WARP2S5_NO_PQ"):
        # escape hatch: the 1216 byte ML-KEM share pushes the ClientHello across
        # two Initial packets, and some paths drop exactly that shape
        log.info("post-quantum offering disabled (WAYGATE_NO_PQ)")
        return False
    if mlkem is None or not hasattr(mlkem, "MLKEM768PrivateKey"):
        log.warning("this cryptography build has no ML-KEM, staying on X25519")
        return False

    original_push_client_hello = tls.push_client_hello
    original_decode_public_key = tls.decode_public_key

    def push_client_hello(buf, hello):  # type: ignore[no-untyped-def]
        if hello.key_share is not None:
            if _PENDING:
                hybrid = _PENDING.pop()
                # insert first: the server is expected to prefer the hybrid group
                hello.key_share.insert(0, (_group_id(), hybrid.key_share_payload))
                if hello.supported_groups is not None:
                    hello.supported_groups.insert(0, _group_id())
            log.info(
                "client hello: key_shares=%s supported_groups=%s",
                [(hex(g), len(d)) for g, d in hello.key_share],
                [hex(g) for g in (hello.supported_groups or [])],
            )
            if os.environ.get("WAYGATE_PQ_ONLY") or os.environ.get("WARP2S5_PQ_ONLY"):
                keep = {_group_id(), 0x001D}
                hello.key_share[:] = [e for e in hello.key_share if e[0] in keep]
                hello.supported_groups[:] = [
                    g for g in (hello.supported_groups or []) if g in keep
                ]
                log.info(
                    "pruned to key_shares=%s supported_groups=%s",
                    [hex(g) for g, _ in hello.key_share],
                    [hex(g) for g in hello.supported_groups],
                )
        else:
            log.warning("client hello has no key_share list")
        original_push_client_hello(buf, hello)

    def decode_public_key(key_share):  # type: ignore[no-untyped-def]
        if key_share is not None:
            log.info("server chose group %s (%d bytes)", hex(key_share[0]), len(key_share[1]))
        if key_share is not None and key_share[0] == GROUP_X25519MLKEM768:
            payload = key_share[1]
            ciphertext = payload[:MLKEM768_CIPHERTEXT_SIZE]
            peer = real_x25519.X25519PublicKey.from_public_bytes(
                payload[MLKEM768_CIPHERTEXT_SIZE:MLKEM768_CIPHERTEXT_SIZE + 32]
            )
            _PEER_CIPHERTEXTS[id(peer)] = ciphertext
            return peer
        return original_decode_public_key(key_share)

    tls.x25519 = _X25519Shim  # type: ignore[assignment]
    tls.push_client_hello = push_client_hello  # type: ignore[assignment]
    tls.decode_public_key = decode_public_key  # type: ignore[assignment]

    # the hybrid key pair is created whenever aioquic generates its X25519 key
    original_generate = _HybridPrivateKey.__init__

    def generate(cls=None):  # type: ignore[no-untyped-def]
        hybrid = _HybridPrivateKey()
        _PENDING.append(hybrid)
        return hybrid

    _HybridPrivateKey.generate = staticmethod(generate)  # type: ignore[attr-defined]
    _ = original_generate
    _APPLIED = True
    log.info("post-quantum MASQUE enabled (X25519MLKEM768)")
    return True


def pad_client_hello(size: int = 0) -> None:
    """Kept for compatibility: sizing alone does not change anything."""
    _ = size
