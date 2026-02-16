"""Address command - generate Bitcoin addresses from mnemonics."""

import click
from ...wallet.addresses import HDWallet
from ..utils import error_message


@click.command()
@click.argument("mnemonic", required=True)
@click.option(
    "-p", "--passphrase",
    default="",
    help="BIP39 passphrase (default: empty)"
)
@click.option(
    "--account",
    type=int,
    default=0,
    help="Account index (default: 0)"
)
@click.option(
    "--change",
    type=int,
    default=0,
    help="Change type: 0=external, 1=internal (default: 0)"
)
@click.option(
    "--index",
    "start_index",
    type=int,
    default=0,
    help="Starting address index (default: 0)"
)
@click.option(
    "-c", "--count",
    type=int,
    default=1,
    help="Number of addresses to generate (default: 1)"
)
@click.option(
    "-f", "--format",
    "address_format",
    type=click.Choice(["P2PKH", "P2SH", "Bech32"], case_sensitive=False),
    default="P2PKH",
    help="Address format: P2PKH (1...), P2SH (3...), Bech32 (bc1...) (default: P2PKH)"
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON"
)
def address(
    mnemonic: str,
    passphrase: str,
    account: int,
    change: int,
    start_index: int,
    count: int,
    address_format: str,
    output_json: bool
) -> None:
    """Generate Bitcoin addresses from mnemonic using BIP32/BIP44.

    MNEMONIC should be a space-separated list of words.

    Address formats:
      - P2PKH (BIP44): Legacy addresses starting with '1'
      - P2SH (BIP49): SegWit-wrapped addresses starting with '3'
      - Bech32 (BIP84): Native SegWit addresses starting with 'bc1'

    Examples:
        bip39-gpu address "word1 word2 ... word12"
        bip39-gpu address "mnemonic..." --format Bech32 --count 5
        bip39-gpu address "mnemonic..." --account 1 --change 1 --index 10
    """
    try:
        # Create HD wallet
        wallet = HDWallet(mnemonic, passphrase=passphrase)

        # Generate addresses
        if count == 1:
            # Single address
            addr = wallet.derive_address(
                account=account,
                change=change,
                address_index=start_index,
                format=address_format
            )

            if output_json:
                import json
                data = {
                    "address": addr,
                    "format": address_format,
                    "derivation_path": f"m/{_get_purpose(address_format)}'/0'/{account}'/{change}/{start_index}",
                    "account": account,
                    "change": change,
                    "index": start_index
                }
                click.echo(json.dumps(data, indent=2))
            else:
                click.echo(f"Address ({address_format}):")
                click.echo(addr)
                click.echo()
                click.echo(f"Derivation: m/{_get_purpose(address_format)}'/0'/{account}'/{change}/{start_index}")

        else:
            # Multiple addresses
            addrs = wallet.derive_addresses(
                count=count,
                start_index=start_index,
                account=account,
                change=change,
                format=address_format
            )

            if output_json:
                import json
                data = {
                    "addresses": addrs,
                    "format": address_format,
                    "count": count,
                    "account": account,
                    "change": change,
                    "start_index": start_index
                }
                click.echo(json.dumps(data, indent=2))
            else:
                click.echo(f"Generated {count} {address_format} addresses:")
                click.echo()
                for i, addr in enumerate(addrs):
                    index = start_index + i
                    click.echo(f"  [{index}] {addr}")
                click.echo()
                click.echo(f"Derivation: m/{_get_purpose(address_format)}'/0'/{account}'/{change}/[{start_index}-{start_index + count - 1}]")

    except ImportError as e:
        click.echo(
            error_message(
                "bip-utils is required for address generation. "
                "Install with: pip install bip-utils",
                as_json=output_json
            ),
            err=True
        )
        raise click.Abort()

    except Exception as e:
        click.echo(error_message(str(e), as_json=output_json), err=True)
        raise click.Abort()


def _get_purpose(format: str) -> int:
    """Get BIP purpose number for address format."""
    purposes = {
        "P2PKH": 44,
        "P2SH": 49,
        "Bech32": 84,
    }
    return purposes.get(format, 44)
