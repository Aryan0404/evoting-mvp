# backend/app/services/election_keys.py
"""
The election public key, read from the public bulletin board.

The trustees' key ceremony (tools/election_setup.py) publishes the Paillier
modulus n at `election:public_n` on the bulletin board; the trustees keep their
decryption shares. Vote collectors need only n to verify ballot proofs.
"""

from __future__ import annotations

from typing import Optional

from app.redis_client import get_bulletin
from app.services.ballot_proof import PublicParams

_PP: Optional[PublicParams] = None
_N_HEX: Optional[str] = None


async def get_public_params() -> Optional[PublicParams]:
    global _PP, _N_HEX
    bb = await get_bulletin()
    n_hex = await bb.get("election:public_n")
    if n_hex is None:
        return None
    if n_hex != _N_HEX:                      # new election key published
        _PP, _N_HEX = PublicParams.from_n(int(n_hex, 16)), n_hex
    return _PP
