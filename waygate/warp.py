"""Cloudflare WARP account registration + identity persistence.

The real WARP clients talk to ``api.cloudflareclient.com``; this module does the
same thing with a minimal payload (the one the Android/desktop clients send) and
then keeps the resulting identity in a JSON file so we only register once.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509 import NameOID

log = logging.getLogger("waygate.warp")

API_BASE = "https://api.cloudflareclient.com/v0a4005"
CLIENT_VERSION = "a-6.30-3596"
USER_AGENT = "okhttp/3.12.1"

#: the API surface the official MASQUE capable clients use
API_BASE_MASQUE = "https://api.cloudflareclient.com/v0a4471"
CLIENT_VERSION_MASQUE = "a-6.35-4471"
USER_AGENT_MASQUE = "WARP for Android"

#: SNI of the consumer MASQUE endpoint
MASQUE_SNI = "consumer-masque.cloudflareclient.com"
#: anycast addresses the MASQUE endpoint lives on (the official client uses 162.159.198.2)
MASQUE_ENDPOINTS_V4 = ("162.159.198.2", "162.159.198.1", "162.159.197.2", "162.159.197.1")
#: IPv6 anycast - on censored networks the v6 path to Cloudflare is often
#: filtered much less than v4 (verified on China Telecom: v6 carries the
#: MASQUE data plane while v4 endpoints flap between resets and timeouts)
MASQUE_ENDPOINTS_V6 = ("2606:4700:103::2", "2606:4700:103::1")
MASQUE_PORT = 443
#: ports the official client was observed trying (443 first, then the alternates)
MASQUE_PORTS = (443, 500, 8095, 1701, 4500, 8443)

#: anycast prefixes the WARP wireguard endpoints live in (same list warp-plus uses)
ENDPOINT_PREFIXES_V4 = (
    "162.159.192.",
    "162.159.195.",
    "188.114.96.",
    "188.114.97.",
    "188.114.98.",
    "188.114.99.",
)
ENDPOINT_PREFIXES_V6 = ("2606:4700:d0::", "2606:4700:d1::")
ENDPOINT_PREFIX_V6 = ENDPOINT_PREFIXES_V6[0]
#: ports the WARP wireguard endpoints are known to listen on
ENDPOINT_PORTS = (2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894)


@dataclass
class WarpIdentity:
    """Everything needed to bring the tunnel up."""

    private_key: str  # base64 raw 32 byte x25519 key
    peer_public_key: str  # base64
    address_v4: str
    address_v6: str
    client_id: str  # base64 -> 3 reserved bytes
    device_id: str = ""
    token: str = ""
    account_type: str = ""
    endpoint_host: str = "engage.cloudflareclient.com:2408"
    endpoint_v4: str = ""
    endpoint_v6: str = ""
    ports: list[int] = field(default_factory=lambda: list(ENDPOINT_PORTS[:4]))
    #: "wireguard" or "masque"
    transport: str = "wireguard"
    #: PKCS#8 PEM client key + certificate used to authenticate the MASQUE tunnel
    ec_private_key: str = ""
    ec_certificate: str = ""
    sni: str = ""

    # ---------------------------------------------------------------- helpers
    @property
    def reserved(self) -> bytes:
        try:
            raw = base64.b64decode(self.client_id)
        except Exception:
            return b"\x00\x00\x00"
        return (raw + b"\x00\x00\x00")[:3]

    def to_json(self) -> dict:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}  # type: ignore[attr-defined]

    @classmethod
    def from_json(cls, data: dict) -> "WarpIdentity":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, path: os.PathLike | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path: os.PathLike | str) -> "WarpIdentity":
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def wg_quick_config(self) -> str:
        """Render a classic wg-quick style config (handy for other clients)."""
        return (
            "[Interface]\n"
            f"PrivateKey = {self.private_key}\n"
            f"Address = {self.address_v4}/32\n"
            f"Address = {self.address_v6}/128\n"
            "DNS = 1.1.1.1\n"
            "MTU = 1280\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {self.peer_public_key}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"Endpoint = {self.endpoint_host}\n"
            "PersistentKeepalive = 25\n"
            f"# Reserved = {base64.b64encode(self.reserved).decode()}\n"
        )


def generate_private_key() -> tuple[str, str]:
    """Return ``(private_b64, public_b64)`` for a fresh x25519 key pair."""
    key = X25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def _request(
    method: str,
    url: str,
    body: dict | None = None,
    token: str | None = None,
    timeout: float = 30.0,
    *,
    user_agent: str = USER_AGENT,
    client_version: str = CLIENT_VERSION,
) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json; charset=UTF-8")
    req.add_header("Accept", "application/json; charset=UTF-8")
    req.add_header("User-Agent", user_agent)
    req.add_header("CF-Client-Version", client_version)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


async def register(timeout: float = 30.0, *, use_masque_api: bool = False) -> WarpIdentity:
    """Create a brand new (free) WARP device and return its identity."""
    private_key, public_key = generate_private_key()
    body = {
        "install_id": "",
        "fcm_token": "",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "key": public_key,
        "type": "Android",
        "model": "PC",
        "locale": "en_US",
        "warp_enabled": True,
    }
    log.info("registering a new WARP device ...")
    api_base = API_BASE_MASQUE if use_masque_api else API_BASE
    data = await asyncio.to_thread(
        lambda: _request(
            "POST",
            f"{api_base}/reg",
            body,
            None,
            timeout,
            user_agent=USER_AGENT_MASQUE if use_masque_api else USER_AGENT,
            client_version=CLIENT_VERSION_MASQUE if use_masque_api else CLIENT_VERSION,
        )
    )
    identity = identity_from_api(data, private_key)
    log.info(
        "registered device %s (account %s, address %s)",
        identity.device_id,
        identity.account_type,
        identity.address_v4,
    )
    return identity


def identity_from_api(data: dict, private_key: str) -> WarpIdentity:
    config = data.get("config") or {}
    peers = config.get("peers") or [{}]
    peer = peers[0]
    endpoint = peer.get("endpoint") or {}
    addresses = (config.get("interface") or {}).get("addresses") or {}
    ports = endpoint.get("ports") or list(ENDPOINT_PORTS[:4])
    return WarpIdentity(
        private_key=private_key,
        peer_public_key=peer.get("public_key", ""),
        address_v4=addresses.get("v4", ""),
        address_v6=addresses.get("v6", ""),
        client_id=config.get("client_id", ""),
        device_id=data.get("id", ""),
        token=data.get("token", ""),
        account_type=(data.get("account") or {}).get("account_type", ""),
        endpoint_host=endpoint.get("host", "engage.cloudflareclient.com:2408"),
        endpoint_v4=endpoint.get("v4", ""),
        endpoint_v6=endpoint.get("v6", ""),
        ports=list(ports),
    )


async def load_or_register(
    path: os.PathLike | str, force: bool = False, transport: str = "wireguard"
) -> WarpIdentity:
    """Load a usable identity for ``transport``, registering one when needed."""
    path = Path(path)
    if transport == "masque":
        return await load_or_register_masque(path, force)
    if path.exists() and not force:
        try:
            identity = WarpIdentity.load(path)
            if identity.private_key and identity.peer_public_key:
                log.debug("loaded existing WARP identity from %s", path)
                identity.transport = "wireguard"
                return identity
        except Exception as exc:  # corrupt file -> re-register
            log.warning("could not read %s (%s), registering again", path, exc)
    identity = await register()
    identity.transport = "wireguard"
    identity.save(path)
    return identity


def masque_identity_path(path: os.PathLike | str) -> Path:
    """``identity.json`` -> ``identity-masque.json`` (MASQUE uses its own device)."""
    path = Path(path)
    return path.with_name(f"{path.stem}-masque{path.suffix}")


def generate_masque_certificate() -> tuple[str, str, str]:
    """Create the EC P-256 key + self signed certificate MASQUE authenticates with.

    Returns ``(certificate_pem, private_key_pem, public_key_spki_b64)`` - the last
    value is what goes into the WARP API (``key_type: secp256r1``).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "waygate")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_key_b64 = base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    return certificate_pem, private_key_pem, public_key_b64


async def enroll_masque_key(
    identity: WarpIdentity, public_key_b64: str, timeout: float = 30.0
) -> dict:
    """PATCH the device so it authenticates with our EC key over MASQUE."""
    url = f"{API_BASE_MASQUE}/reg/{identity.device_id}"
    body = {
        "key": public_key_b64,
        "key_type": "secp256r1",
        "tunnel_type": "masque",
    }
    return await asyncio.to_thread(
        lambda: _request(
            "PATCH",
            url,
            body,
            identity.token,
            timeout,
            user_agent=USER_AGENT_MASQUE,
            client_version=CLIENT_VERSION_MASQUE,
        )
    )


async def get_device(identity: WarpIdentity, timeout: float = 30.0) -> dict:
    url = f"{API_BASE_MASQUE}/reg/{identity.device_id}"
    return await asyncio.to_thread(
        lambda: _request(
            "GET",
            url,
            None,
            identity.token,
            timeout,
            user_agent=USER_AGENT_MASQUE,
            client_version=CLIENT_VERSION_MASQUE,
        )
    )


async def register_masque(timeout: float = 30.0) -> WarpIdentity:
    """Register a device and enroll it for MASQUE (EC key + self signed cert)."""
    certificate_pem, private_key_pem, public_key_b64 = generate_masque_certificate()
    identity = await register(timeout, use_masque_api=True)
    identity.transport = "masque"
    identity.ec_certificate = certificate_pem
    identity.ec_private_key = private_key_pem
    identity.sni = MASQUE_SNI
    log.info("enrolling the MASQUE key for device %s ...", identity.device_id[:8])
    try:
        data = await enroll_masque_key(identity, public_key_b64, timeout)
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:200].decode("utf-8", "replace")
        raise RuntimeError(f"MASQUE enrollment failed: HTTP {exc.code} {detail}") from exc
    _apply_config(identity, data)
    return identity


def _apply_config(identity: WarpIdentity, data: dict) -> None:
    """Update an identity from an API device payload (addresses, endpoints)."""
    config = data.get("config") or {}
    if not config:
        return
    addresses = (config.get("interface") or {}).get("addresses") or {}
    if addresses.get("v4"):
        identity.address_v4 = addresses["v4"]
    if addresses.get("v6"):
        identity.address_v6 = addresses["v6"]
    if config.get("client_id"):
        identity.client_id = config["client_id"]
    peers = config.get("peers") or [{}]
    endpoint = peers[0].get("endpoint") or {}
    if endpoint.get("v4"):
        identity.endpoint_v4 = endpoint["v4"]
    if endpoint.get("v6"):
        identity.endpoint_v6 = endpoint["v6"]
    if endpoint.get("host"):
        identity.endpoint_host = endpoint["host"]


async def load_or_register_masque(path: os.PathLike | str, force: bool = False) -> WarpIdentity:
    """Load (or create) the MASQUE identity used for the cf-connect-ip tunnel."""
    path = Path(path)
    if path.exists() and not force:
        try:
            identity = WarpIdentity.load(path)
            if identity.ec_private_key and identity.ec_certificate and identity.device_id:
                identity.transport = "masque"
                return identity
        except Exception as exc:  # noqa: BLE001
            log.warning("could not read %s (%s), registering again", path, exc)
    identity = await register_masque()
    identity.save(path)
    return identity


async def update_license(identity: WarpIdentity, license_key: str) -> dict:
    """Attach a WARP+ / Zero Trust license key to an existing device."""
    url = f"{API_BASE}/reg/{identity.device_id}/account"
    try:
        data = await asyncio.to_thread(
            _request, "PUT", url, {"license": license_key}, identity.token
        )
    except urllib.error.HTTPError:
        data = await asyncio.to_thread(
            _request, "POST", url + "/license", {"license": license_key}, identity.token
        )
    return data
