#!/usr/bin/env python3
"""
secret_guard.py — Zero-Leak Secret Scanner & Symmetric Encryption Guard (JZacharie)
====================================================================================
Empêche tout commit ou push contenant un PAT (Personal Access Token), une clé privée
ou un secret en clair qui n'est pas chiffré symétriquement via `SECRET_ENCRYPTION_KEY`.

Commandes :
  python .github/scripts/secret_guard.py scan [--staged | --all]
  python .github/scripts/secret_guard.py verify-encrypted [--require-key]
  python .github/scripts/secret_guard.py encrypt "<plaintext>"
  python .github/scripts/secret_guard.py decrypt "ENC[AES256_GCM_SIV,...]"
  python .github/scripts/secret_guard.py encrypt-file <path>
  python .github/scripts/secret_guard.py decrypt-file <path.enc>
"""

import argparse
import base64
import hashlib
import hmac
import math
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ENVELOPE_PREFIX = "ENC[SYM256,"
ENVELOPE_REGEX = re.compile(
    r"ENC\[(?:SYM256|AES256_GCM|AES256_PBKDF2),salt:([A-Za-z0-9+/=_-]+),iv:([A-Za-z0-9+/=_-]+),tag:([A-Za-z0-9+/=_-]+),data:([A-Za-z0-9+/=_-]+)\]"
)

# Motifs haute confiance de PATs et secrets critiques (interdits en clair)
HIGH_CONFIDENCE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("GitHub Classic PAT (ghp_)", re.compile(r"\bghp_[A-Za-z0-9]{36,}\b")),
    ("GitHub Fine-Grained PAT (github_pat_)", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{80,}\b")),
    ("GitHub OAuth/App Token (gho_/ghu_/ghs_/ghr_)", re.compile(r"\bgh[ousr]_[A-Za-z0-9]{36,}\b")),
    ("GitLab PAT (glpat-)", re.compile(r"\bglpat-[A-Za-z0-9\-=_]{20,}\b")),
    ("Slack Token (xoxb/xoxp/xoxa/xoxr)", re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b")),
    ("OpenAI / API Secret Key (sk-)", re.compile(r"\bsk-(?:proj-|ant-api03-)?[A-Za-z0-9_\-]{32,}\b")),
    ("HuggingFace Token (hf_)", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("AWS Access Key ID (AKIA/ASIA)", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google Cloud API Key (AIza)", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Private Key PEM Block", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    (
        "URL with Embedded Token/Password",
        re.compile(
            r"(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^/\s:@\"'`]+:[^/\s:@\"'`]{6,}@(?!localhost|127\.0\.0\.1|example\.com|postgres|db|redis|minio)[^/\s\"'`]+"
        ),
    ),
]

# Fichiers sensibles qui ne doivent jamais être committés en clair
FORBIDDEN_FILENAME_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("Fichier de clé privée SSH", re.compile(r"(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)$")),
    ("Fichier de credentials Git", re.compile(r"(?:^|/)\.git-credentials$")),
    ("Clé privée non chiffrée (.pem/.key)", re.compile(r"(?:^|/)[^/]+\.(?:pem|key)$")),
]

IGNORED_DIRS = {
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
}

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".exe", ".dll", ".so",
    ".dylib", ".rlib", ".rmeta", ".pyc", ".lock",
}

SAFE_PLACEHOLDERS = {
    "changeme", "placeholder", "your_token_here", "your-api-key",
    "example", "dummy", "secret", "password", "none", "null", "true", "false",
    "todo", "fixme", "test", "mock", "default", "REDACTED",
}


def _derive_keys(master_key: str, salt: bytes) -> Tuple[bytes, bytes]:
    """Dérive une clé de chiffrement (32o) et une clé MAC (32o) via PBKDF2-HMAC-SHA256."""
    dk = hashlib.pbkdf2_hmac("sha256", master_key.encode("utf-8"), salt, 200_000, dklen=64)
    return dk[:32], dk[32:]


def _keystream_xor(data: bytes, enc_key: bytes, iv: bytes) -> bytes:
    """Chiffrement par flot CTR déterministe basé sur HMAC-SHA256 (stdlib pure)."""
    out = bytearray(len(data))
    block_count = math.ceil(len(data) / 32)
    for counter in range(block_count):
        ctr_bytes = counter.to_bytes(8, "big")
        block = hmac.new(enc_key, iv + ctr_bytes, hashlib.sha256).digest()
        start = counter * 32
        end = min(start + 32, len(data))
        for i in range(start, end):
            out[i] = data[i] ^ block[i - start]
    return bytes(out)


def encrypt_secret(plaintext: str, master_key: str) -> str:
    """Chiffre un secret en enveloppe authentifiée ENC[SYM256,salt:...,iv:...,tag:...,data:...]."""
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(master_key, salt)
    ciphertext = _keystream_xor(plaintext.encode("utf-8"), enc_key, iv)
    tag = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest()
    return (
        f"ENC[SYM256,"
        f"salt:{base64.b64encode(salt).decode('ascii')},"
        f"iv:{base64.b64encode(iv).decode('ascii')},"
        f"tag:{base64.b64encode(tag).decode('ascii')},"
        f"data:{base64.b64encode(ciphertext).decode('ascii')}]"
    )


def decrypt_secret(envelope: str, master_key: str) -> str:
    """Vérifie le tag HMAC-SHA256 et déchiffre une enveloppe ENC[SYM256,...]."""
    m = ENVELOPE_REGEX.fullmatch(envelope.strip())
    if not m:
        raise ValueError("Format d'enveloppe invalide (attendu: ENC[SYM256,salt:...,iv:...,tag:...,data:...])")
    salt = base64.b64decode(m.group(1))
    iv = base64.b64decode(m.group(2))
    expected_tag = base64.b64decode(m.group(3))
    ciphertext = base64.b64decode(m.group(4))
    enc_key, mac_key = _derive_keys(master_key, salt)
    actual_tag = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, actual_tag):
        raise ValueError("Échec d'authentification HMAC : clé symétrique invalide ou secret altéré !")
    plaintext = _keystream_xor(ciphertext, enc_key, iv)
    return plaintext.decode("utf-8")


def get_master_key(required: bool = False) -> Optional[str]:
    """Récupère la clé symétrique depuis SECRET_ENCRYPTION_KEY ou ~/.config/jzacharie/secret_encryption.key."""
    key = os.environ.get("SECRET_ENCRYPTION_KEY", "").strip()
    if key:
        return key
    key_file = Path.home() / ".config" / "jzacharie" / "secret_encryption.key"
    if key_file.is_file():
        key = key_file.read_text(encoding="utf-8").strip()
        if key:
            return key
    if required:
        print(
            "❌ ERREUR : La clé symétrique SECRET_ENCRYPTION_KEY est introuvable.\n"
            "   -> En CI GitHub Actions : configurez le secret de dépôt `SECRET_ENCRYPTION_KEY`.\n"
            "   -> En local : définissez $env:SECRET_ENCRYPTION_KEY ou ~/.config/jzacharie/secret_encryption.key.",
            file=sys.stderr,
        )
        sys.exit(2)
    return None


def check_git_config_remotes(repo_root: Path) -> List[str]:
    """Vérifie qu'aucun PAT ou mot de passe n'est présent dans .git/config."""
    errors = []
    git_config = repo_root / ".git" / "config"
    if not git_config.is_file():
        return errors
    try:
        content = git_config.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return errors
    for idx, line in enumerate(content.splitlines(), start=1):
        if re.search(r"https?://[^/\s:@]+:[^/\s:@]+@", line) or re.search(r"\b(?:ghp_|github_pat_|glpat-)", line):
            errors.append(
                f"[.git/config:{idx}] 🚨 CRITIQUE : PAT ou identifiant en clair détecté dans .git/config !"
            )
    return errors


def is_line_allowlisted(line: str) -> bool:
    """Ignore les lignes contenant explicitement une enveloppe chiffrée ENC[...] ou secret-guard:ignore."""
    if "secret-guard:ignore" in line or "gitleaks:allow" in line:
        return True
    # Remove any valid ENC[...] envelopes before checking
    stripped = ENVELOPE_REGEX.sub("REDACTED_ENC", line)
    if stripped != line and not any(p.search(stripped) for _, p in HIGH_CONFIDENCE_PATTERNS):
        return True
    return False


def scan_file_content(rel_path: str, content: str) -> List[str]:
    """Analyse le contenu d'un fichier à la recherche de secrets non chiffrés."""
    findings = []
    norm_path = rel_path.replace("\\", "/")

    # Ignore self
    if norm_path.endswith("secret_guard.py") or norm_path.endswith(".gitleaks.toml"):
        return findings

    for label, fpat in FORBIDDEN_FILENAME_PATTERNS:
        if fpat.search(norm_path):
            if "PRIVATE KEY-----" in content and "ENC[" not in content:
                findings.append(f"[{norm_path}] 🚨 {label} committé sans chiffrement symétrique ENC[...]")

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        if len(raw_line) > 4000 or is_line_allowlisted(raw_line):
            continue
        line_without_enc = ENVELOPE_REGEX.sub("", raw_line)
        for rule_name, pattern in HIGH_CONFIDENCE_PATTERNS:
            m = pattern.search(line_without_enc)
            if m:
                matched = m.group(0)
                low = matched.lower()
                if any(ph in low for ph in SAFE_PLACEHOLDERS) or "xxxx" in low or "..." in low:
                    continue
                preview = matched[:6] + "..." + matched[-4:] if len(matched) > 14 else "***"
                findings.append(
                    f"[{norm_path}:{line_no}] 🚨 {rule_name} détecté en clair ({preview}) ! "
                    f"Chiffrez-le avec : python .github/scripts/secret_guard.py encrypt \"<secret>\""
                )
    return findings


def list_target_files(repo_root: Path, staged_only: bool) -> List[Path]:
    """Liste les fichiers à scanner (staged uniquement ou tout l'arbre Git)."""
    cmd = (
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"]
        if staged_only
        else ["git", "ls-files"]
    )
    res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        return []
    files = []
    for line in res.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        p = repo_root / rel
        if not p.is_file():
            continue
        if any(part in IGNORED_DIRS for part in Path(rel).parts):
            continue
        if p.suffix.lower() in IGNORED_EXTENSIONS:
            continue
        files.append(p)
    return files


def cmd_scan(repo_root: Path, staged_only: bool) -> int:
    errors = check_git_config_remotes(repo_root)
    files = list_target_files(repo_root, staged_only=staged_only)
    for fpath in files:
        rel = str(fpath.relative_to(repo_root))
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        errors.extend(scan_file_content(rel, content))

    if errors:
        print("==================================================================", file=sys.stderr)
        print("🛑 SECRET-GUARD : FUITE DE SECRET / PAT EN CLAIR BLOQUÉE !", file=sys.stderr)
        print("==================================================================", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print("\n💡 Tous les secrets doivent être chiffrés symétriquement via :", file=sys.stderr)
        print("   python .github/scripts/secret_guard.py encrypt \"<votre_secret>\"", file=sys.stderr)
        return 1

    mode = "staged" if staged_only else "all tracked files"
    print(f"✅ Secret-Guard : Aucun PAT ou secret en clair détecté ({len(files)} fichiers vérifiés [{mode}]).")
    return 0


def cmd_verify_encrypted(repo_root: Path, require_key: bool) -> int:
    files = list_target_files(repo_root, staged_only=False)
    envelopes: List[Tuple[str, int, str]] = []
    for fpath in files:
        rel = str(fpath.relative_to(repo_root)).replace("\\", "/")
        if rel.endswith("secret_guard.py"):
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for idx, line in enumerate(content.splitlines(), start=1):
            for m in ENVELOPE_REGEX.finditer(line):
                envelopes.append((rel, idx, m.group(0)))

    master_key = get_master_key(required=require_key or bool(envelopes))
    if not envelopes:
        if master_key:
            print("✅ Secret-Guard : Clé symétrique SECRET_ENCRYPTION_KEY présente (0 enveloppe ENC[...] dans le dépôt).")
        else:
            print("ℹ️ Secret-Guard : 0 enveloppe ENC[...] trouvée dans le dépôt.")
        return 0

    failures = []
    for rel, line_no, env_str in envelopes:
        try:
            decrypted = decrypt_secret(env_str, master_key)
            # Masque automatiquement la valeur dans GitHub Actions
            if os.environ.get("GITHUB_ACTIONS") == "true" and decrypted:
                print(f"::add-mask::{decrypted}")
        except Exception as exc:
            failures.append(f"[{rel}:{line_no}] {exc}")

    if failures:
        print("🛑 SECRET-GUARD : ÉCHEC DE VÉRIFICATION DES SECRETS CHIFFRÉS !", file=sys.stderr)
        for fail in failures:
            print(f"  {fail}", file=sys.stderr)
        return 1

    print(f"✅ Secret-Guard : {len(envelopes)} secret(s) chiffré(s) ENC[...] authentifié(s) avec succès via SECRET_ENCRYPTION_KEY.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Zero-Leak Secret Guard & Symmetric Encryption CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scanne les fichiers pour bloquer tout PAT ou secret en clair")
    p_scan.add_argument("--staged", action="store_true", help="Scanne uniquement les fichiers indexés (git diff --cached)")
    p_scan.add_argument("--all", action="store_true", help="Scanne tous les fichiers suivis par Git")

    p_ver = sub.add_parser("verify-encrypted", help="Vérifie l'intégrité HMAC/AES de tous les secrets ENC[...]")
    p_ver.add_argument("--require-key", action="store_true", help="Exige que SECRET_ENCRYPTION_KEY soit défini")

    p_enc = sub.add_parser("encrypt", help="Chiffre une chaîne avec SECRET_ENCRYPTION_KEY")
    p_enc.add_argument("plaintext", help="Valeur secrète à chiffrer")

    p_dec = sub.add_parser("decrypt", help="Déchiffre une enveloppe ENC[SYM256,...]")
    p_dec.add_argument("envelope", help="Enveloppe ENC[...] à déchiffrer")

    p_encf = sub.add_parser("encrypt-file", help="Chiffre un fichier entier en <fichier>.enc")
    p_encf.add_argument("path", help="Chemin du fichier en clair")

    p_decf = sub.add_parser("decrypt-file", help="Déchiffre un fichier <fichier>.enc")
    p_decf.add_argument("path", help="Chemin du fichier .enc")

    args = parser.parse_args()
    repo_root = Path.cwd()

    if args.command == "scan":
        return cmd_scan(repo_root, staged_only=args.staged and not args.all)
    elif args.command == "verify-encrypted":
        return cmd_verify_encrypted(repo_root, require_key=args.require_key)
    elif args.command == "encrypt":
        key = get_master_key(required=True)
        print(encrypt_secret(args.plaintext, key))
        return 0
    elif args.command == "decrypt":
        key = get_master_key(required=True)
        print(decrypt_secret(args.envelope, key))
        return 0
    elif args.command == "encrypt-file":
        key = get_master_key(required=True)
        src = Path(args.path)
        env = encrypt_secret(src.read_text(encoding="utf-8"), key)
        dst = Path(str(src) + ".enc")
        dst.write_text(env + "\n", encoding="utf-8")
        print(f"✅ Fichier chiffré écrit dans : {dst}")
        return 0
    elif args.command == "decrypt-file":
        key = get_master_key(required=True)
        src = Path(args.path)
        plain = decrypt_secret(src.read_text(encoding="utf-8").strip(), key)
        out_path = Path(str(src)[:-4]) if str(src).endswith(".enc") else Path(str(src) + ".dec")
        out_path.write_text(plain, encoding="utf-8")
        print(f"✅ Fichier déchiffré écrit dans : {out_path}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
