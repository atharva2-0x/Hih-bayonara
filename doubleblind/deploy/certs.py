"""Generate the per-zone PKI for the Docker deployment.

    python -m doubleblind certs --out infra/certs/out

One CA per zone; short-lived (30 day) EC P-256 leaf certificates; each zone's
directory contains only what that zone needs, and is the only certs
directory mounted into that zone's containers:

    authority/  server + client cert, CAs of red/blue/obs (listener trust),
                CAs of enclave/model/obs (to verify servers it calls)
    red/, blue/ client cert + authority CA
    enclave/    server + client cert, authority CA (listener trust), model CA
    model/      server cert, enclave CA (data port), authority CA (admin port)
    obs/        server + client cert, authority CA
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ZONES = ["authority", "red", "blue", "enclave", "model", "obs"]
SERVER_IPS = {
    "authority": ["10.77.1.10", "10.77.2.10", "10.77.3.10", "10.77.4.10", "10.77.5.10", "10.77.9.10"],
    "enclave": ["10.77.3.20"],
    "model": ["10.77.4.20"],
    "obs": ["10.77.5.20"],
}
SERVER_DNS = {"authority": ["arbiter"], "enclave": ["enclave"], "model": ["model"], "obs": ["obs"]}


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DOUBLE-BLIND"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(zone: str, days: int):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(f"{zone}-ca")).issuer_name(_name(f"{zone}-ca"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, cn: str, *, server: bool, ips: list[str], dns: list[str], days: int):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    eku = [ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage(eku), critical=False))
    if server:
        sans = [x509.IPAddress(ipaddress.ip_address(i)) for i in ips] + [x509.DNSName(d) for d in dns]
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return key, b.sign(ca_key, hashes.SHA256())


def _pem_cert(c) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def _pem_key(k) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def generate(out: str | Path, *, extra_ips: list[str] | None = None, days: int = 30, uid: int = 10001) -> Path:
    out = Path(out)
    cas = {z: _ca(z, days) for z in ZONES}
    extra = extra_ips or []
    files: dict[str, dict[str, bytes]] = {z: {} for z in ZONES}

    def server(z: str) -> None:
        k, c = _leaf(*cas[z], f"{z}-server", server=True, ips=SERVER_IPS.get(z, []) + extra,
                     dns=SERVER_DNS.get(z, []) + (["localhost"] if extra else []), days=days)
        files[z]["server.crt"], files[z]["server.key"] = _pem_cert(c), _pem_key(k)

    def client(z: str) -> None:
        k, c = _leaf(*cas[z], f"{z}-client", server=False, ips=[], dns=[], days=days)
        files[z]["client.crt"], files[z]["client.key"] = _pem_cert(c), _pem_key(k)

    for z in ("authority", "enclave", "model", "obs"):
        server(z)
    for z in ("authority", "red", "blue", "enclave", "obs"):
        client(z)
    trust = {
        "authority": ["red", "blue", "obs", "enclave", "model"],
        "red": ["authority"], "blue": ["authority"],
        "enclave": ["authority", "model"],
        "model": ["enclave", "authority"],
        "obs": ["authority"],
    }
    for z, cas_needed in trust.items():
        for other in cas_needed:
            files[z][f"ca-{other}.crt"] = _pem_cert(cas[other][1])

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    for z, fs in files.items():
        d = out / z
        d.mkdir(parents=True, exist_ok=True)
        for name, data in fs.items():
            p = d / name
            p.write_bytes(data)
            if is_root:
                os.chown(p, uid, uid)
                os.chmod(p, 0o400 if name.endswith(".key") else 0o444)
            else:
                os.chmod(p, 0o644)
        if is_root:
            os.chown(d, uid, uid)
    return out
