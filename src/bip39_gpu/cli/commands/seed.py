"""Seed command - convert mnemonic to seed."""

import click
from ...core.mnemonic import BIP39Mnemonic
from ..utils import format_seed_info, error_message


@click.command()
@click.argument("mnemonic", required=True)
@click.option(
    "-p", "--passphrase",
    default="",
    help="BIP39 passphrase (default: empty)"
)
@click.option(
    "--gpu",
    is_flag=True,
    help="Use GPU acceleration (if available)"
)
@click.option(
    "--hex",
    "hex_output",
    is_flag=True,
    default=True,
    help="Output seed as hex (default)"
)
@click.option(
    "--base64",
    "base64_output",
    is_flag=True,
    help="Output seed as base64"
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON"
)
def seed(
    mnemonic: str,
    passphrase: str,
    gpu: bool,
    hex_output: bool,
    base64_output: bool,
    output_json: bool
) -> None:
    """Convert mnemonic to 64-byte seed using PBKDF2.

    MNEMONIC should be a space-separated list of words.

    The seed is generated using PBKDF2-HMAC-SHA512 with 2048 iterations
    as specified in BIP39.

    Examples:
        bip39-gpu seed "word1 word2 ... word12"
        bip39-gpu seed "abandon abandon ... about" --passphrase "test"
        bip39-gpu seed "mnemonic..." --gpu --json
    """
    try:
        # Determine output format
        use_hex = hex_output if not base64_output else False

        # Generate seed
        seed_bytes = BIP39Mnemonic.to_seed(
            mnemonic,
            passphrase=passphrase,
            use_gpu=gpu
        )

        # Format and output
        output = format_seed_info(
            seed_bytes,
            mnemonic=mnemonic if not output_json else None,
            passphrase=passphrase if passphrase else None,
            as_json=output_json,
            hex_output=use_hex
        )
        click.echo(output)

    except Exception as e:
        click.echo(error_message(str(e), as_json=output_json), err=True)
        raise click.Abort()
