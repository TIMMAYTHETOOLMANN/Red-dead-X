"""
Multi-chain / network catalog.

Port of soex-premiumcvt-audit/scripts/lib/chains.ts.

Pure data + lookups. No network, no SDK calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Vm = Literal["evm", "svm", "btc", "cosmos", "other"]


@dataclass
class ChainInfo:
    key: str
    name: str
    vm: str
    chain_id: int | None
    native_symbol: str
    testnet: bool
    thirdweb_chain_id: int | None


CHAINS: list[ChainInfo] = [
    ChainInfo("ethereum", "Ethereum", "evm", 1, "ETH", False, 1),
    ChainInfo("bsc", "BNB Smart Chain", "evm", 56, "BNB", False, 56),
    ChainInfo("polygon", "Polygon PoS", "evm", 137, "POL", False, 137),
    ChainInfo("arbitrum", "Arbitrum One", "evm", 42161, "ETH", False, 42161),
    ChainInfo("optimism", "OP Mainnet", "evm", 10, "ETH", False, 10),
    ChainInfo("base", "Base", "evm", 8453, "ETH", False, 8453),
    ChainInfo("merlin", "Merlin Chain (Bitcoin L2, EVM-equivalent)", "evm", 4200, "BTC", False, 4200),
    ChainInfo("morph", "Morph (Ethereum L2)", "evm", 2818, "ETH", False, 2818),
    ChainInfo("platon", "PlatON (privacy-preserving)", "evm", 210425, "LAT", False, 210425),
    ChainInfo("solana", "Solana", "svm", None, "SOL", False, None),
    ChainInfo("solana-devnet", "Solana Devnet", "svm", None, "SOL", True, None),
    ChainInfo("bitcoin", "Bitcoin", "btc", None, "BTC", False, None),
]

_BY_KEY: dict[str, ChainInfo] = {c.key: c for c in CHAINS}
_BY_CHAIN_ID: dict[int, ChainInfo] = {
    c.chain_id: c for c in CHAINS if c.chain_id is not None
}


def chain_by_key(key: str) -> ChainInfo | None:
    """Look up a chain by its lower-case key.

    Args:
        key: The chain key (e.g. "ethereum", "solana").

    Returns:
        ChainInfo or None if not found.
    """
    return _BY_KEY.get(key.strip().lower())


def chain_by_chain_id(chain_id: int) -> ChainInfo | None:
    """Look up an EVM chain by numeric id.

    Args:
        chain_id: The EVM chain id.

    Returns:
        ChainInfo or None if not found.
    """
    return _BY_CHAIN_ID.get(chain_id)


def is_evm(chain: ChainInfo) -> bool:
    """True when the chain runs the EVM.

    Args:
        chain: The ChainInfo to check.

    Returns:
        True for EVM chains.
    """
    return chain.vm == "evm"


def resolve_chain(ref: str | int) -> ChainInfo:
    """Resolve a chain reference (key or numeric chain id) to a ChainInfo.

    Args:
        ref: A chain key string or numeric chain id.

    Returns:
        The matching ChainInfo.

    Raises:
        ValueError: If the chain is not found.
    """
    found = chain_by_chain_id(ref) if isinstance(ref, int) else chain_by_key(str(ref))
    if not found:
        raise ValueError(
            f'Unknown chain "{ref}". Add it to engine/chains.py before analyzing '
            "(routing the wrong VM produces meaningless findings)."
        )
    return found


def evm_chains() -> list[ChainInfo]:
    """All EVM chains in the catalog.

    Returns:
        List of ChainInfo for EVM chains.
    """
    return [c for c in CHAINS if is_evm(c)]
