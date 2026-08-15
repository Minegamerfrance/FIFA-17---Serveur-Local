"""Origin LSX AES-128-ECB + LCG key derivation (origin-sdk / src/lsx/crypto.ts)."""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

KEY_SIZE = 16
DEFAULT_SEED = 7
RAND_MAX = 32767
MULTIPLIER = 214013
INCREMENT = 2531011


class LsxRandom:
    def __init__(self, seed: int) -> None:
        self.seed = seed & 0xFFFFFFFF

    def next(self) -> int:
        self.seed = (self.seed * MULTIPLIER + INCREMENT) & 0xFFFFFFFF
        return (self.seed >> 16) & RAND_MAX

    def set_seed(self, seed: int) -> None:
        self.seed = seed & 0xFFFFFFFF


@dataclass
class LsxCrypto:
    key: bytes

    @classmethod
    def from_seed(cls, seed: int = 0) -> "LsxCrypto":
        return cls(key=cls._key_from_seed(seed))

    @staticmethod
    def _key_from_seed(seed: int) -> bytes:
        seed &= 0xFFFFFFFF
        if seed == 0:
            return bytes(range(KEY_SIZE))
        rng = LsxRandom(DEFAULT_SEED)
        new_seed = (rng.next() + seed) & 0xFFFFFFFF
        rng.set_seed(new_seed)
        return bytes(rng.next() & 0xFF for _ in range(KEY_SIZE))

    def set_key(self, seed: int) -> None:
        self.key = self._key_from_seed(seed)

    def encrypt(self, plain: str) -> bytes:
        padder = PKCS7(128).padder()
        data = padder.update(plain.encode("utf-8")) + padder.finalize()
        enc = Cipher(algorithms.AES(self.key), modes.ECB()).encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, cipher: bytes) -> str:
        dec = Cipher(algorithms.AES(self.key), modes.ECB()).decryptor()
        padded = dec.update(cipher) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8", errors="replace")

    def prepare_challenge_response(self, challenge_key: str) -> str:
        response_str = self.encrypt(challenge_key).hex()
        seed = (ord(response_str[0]) << 8) | ord(response_str[1])
        self.set_key(seed)
        return response_str

    def apply_session_from_response_hex(self, response_hex: str) -> None:
        seed = (ord(response_hex[0]) << 8) | ord(response_hex[1])
        self.set_key(seed)


class LsxSessionTracker:
    """
    Track LSX session key from Challenge / ChallengeResponse / ChallengeAccepted.

    FIFA 17 + stp-origin_emu (observed): post-handshake AES key is derived from
    ChallengeAccepted.response ASCII seed, which can DIFFER from FIFA's
    ChallengeResponse.response. Prefer Accepted; keep client response as fallback.
    """

    def __init__(self) -> None:
        self.bootstrap = LsxCrypto.from_seed(0)
        self.session: LsxCrypto | None = None
        self.challenge_key: str | None = None
        self.ready = False
        self.key_source: str = "none"
        self.client_response_hex: str | None = None
        self.accepted_response_hex: str | None = None

    def on_plaintext(self, xml: str) -> None:
        import re

        m = re.search(r'Challenge\s+key="([0-9a-fA-F]+)"', xml)
        if m:
            self.challenge_key = m.group(1)
            self.session = None
            self.ready = False
            self.key_source = "none"
            self.client_response_hex = None
            self.accepted_response_hex = None
            return

        m = re.search(r'ChallengeResponse\s+[^>]*\bresponse="([0-9a-fA-F]+)"', xml)
        if m:
            self.client_response_hex = m.group(1)
            c = LsxCrypto.from_seed(0)
            if self.challenge_key:
                produced = c.prepare_challenge_response(self.challenge_key)
                if produced == self.client_response_hex:
                    self.session = c
                    self.key_source = "challenge_response_prepare"
                else:
                    c2 = LsxCrypto.from_seed(0)
                    c2.apply_session_from_response_hex(self.client_response_hex)
                    self.session = c2
                    self.key_source = "challenge_response_hex"
            else:
                c.apply_session_from_response_hex(self.client_response_hex)
                self.session = c
                self.key_source = "challenge_response_hex"
            self.ready = True
            return

        m = re.search(r'ChallengeAccepted\s+[^>]*\bresponse="([0-9a-fA-F]+)"', xml)
        if m:
            resp = m.group(1)
            self.accepted_response_hex = resp
            c = LsxCrypto.from_seed(0)
            c.apply_session_from_response_hex(resp)
            self.session = c
            self.ready = True
            self.key_source = "challenge_accepted_hex"
            return

    @staticmethod
    def _looks_like_lsx(plain: str) -> bool:
        s = plain.lstrip()
        return s.startswith("<LSX>") or s.startswith("<?xml")

    def try_decrypt_hex_ascii(self, text: str) -> str | None:
        plain, _mode = self.try_decrypt_hex_ascii_dual(text)
        return plain

    def try_decrypt_hex_ascii_dual(
        self, text: str, protocol_version: str | None = None
    ) -> tuple[str | None, str]:
        """
        Try ChallengeAccepted key, then ChallengeResponse key, then default 00..0f.
        """
        s = text.strip()
        if len(s) < 32 or len(s) % 2:
            return None, "none"
        if any(c not in "0123456789abcdefABCDEF" for c in s):
            return None, "none"
        try:
            raw = bytes.fromhex(s)
        except ValueError:
            return None, "none"
        if len(raw) % 16:
            return None, "none"

        prefer_default = bool(protocol_version and protocol_version.strip() not in ("", "3"))

        def attempt(crypto: LsxCrypto) -> str | None:
            try:
                plain = crypto.decrypt(raw)
            except Exception:
                return None
            return plain if self._looks_like_lsx(plain) else None

        candidates: list[tuple[str, LsxCrypto]] = []

        if self.accepted_response_hex:
            c = LsxCrypto.from_seed(0)
            c.apply_session_from_response_hex(self.accepted_response_hex)
            candidates.append(("session_accepted", c))

        if self.client_response_hex:
            c = LsxCrypto.from_seed(0)
            c.apply_session_from_response_hex(self.client_response_hex)
            candidates.append(("session_client_response", c))

        if self.ready and self.session:
            candidates.append((f"session_{self.key_source}", self.session))

        default_crypto = LsxCrypto.from_seed(0)
        if prefer_default:
            candidates.insert(0, ("default", default_crypto))
        else:
            candidates.append(("default", default_crypto))

        seen: set[bytes] = set()
        ordered: list[tuple[str, LsxCrypto]] = []
        for mode, crypto in candidates:
            if crypto.key in seen:
                continue
            seen.add(crypto.key)
            ordered.append((mode, crypto))

        for mode, crypto in ordered:
            plain = attempt(crypto)
            if plain is not None:
                return plain, mode
        return None, "none"
