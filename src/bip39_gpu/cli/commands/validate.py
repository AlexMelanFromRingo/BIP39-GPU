"""Validate command - check BIP39 mnemonic validity."""

import click
from ...core.mnemonic import BIP39Mnemonic
from ...core.entropy import WORDS_TO_ENTROPY_BITS
from ..utils import format_mnemonic_info, error_message


@click.command()
@click.argument("mnemonic", required=True)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON"
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Show detailed validation info"
)
def validate(mnemonic: str, output_json: bool, verbose: bool) -> None:
    """Validate a BIP39 mnemonic phrase.

    MNEMONIC should be a space-separated list of words.

    Examples:
        bip39-gpu validate "word1 word2 ... word12"
        bip39-gpu validate "abandon abandon ... about" --verbose
    """
    try:
        is_valid = BIP39Mnemonic.validate(mnemonic)
        word_count = len(mnemonic.split())

        entropy_bits = None
        if is_valid and word_count in WORDS_TO_ENTROPY_BITS:
            entropy_bits = WORDS_TO_ENTROPY_BITS[word_count]

        if verbose or output_json:
            output = format_mnemonic_info(
                mnemonic,
                valid=is_valid,
                entropy_bits=entropy_bits,
                as_json=output_json
            )
            click.echo(output)
        else:
            if is_valid:
                click.echo("✓ Valid mnemonic")
            else:
                click.echo("✗ Invalid mnemonic", err=True)
                raise click.Abort()

        # Exit with appropriate code
        if not is_valid:
            raise click.Abort()

    except Exception as e:
        if "Abort" not in str(e):
            click.echo(error_message(str(e), as_json=output_json), err=True)
        raise click.Abort()
