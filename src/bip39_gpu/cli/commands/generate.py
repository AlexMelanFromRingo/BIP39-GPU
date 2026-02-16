"""Generate command - create random BIP39 mnemonics."""

import click
from ...core.mnemonic import BIP39Mnemonic
from ...core.entropy import WORDS_TO_ENTROPY_BITS
from ..utils import format_mnemonic_info, error_message


@click.command()
@click.option(
    "-w", "--words",
    type=click.Choice(["12", "15", "18", "21", "24"]),
    default="12",
    help="Number of words in mnemonic (default: 12)"
)
@click.option(
    "-c", "--count",
    type=int,
    default=1,
    help="Number of mnemonics to generate (default: 1)"
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON"
)
def generate(words: str, count: int, output_json: bool) -> None:
    """Generate random BIP39 mnemonic phrases.

    Examples:
        bip39-gpu generate
        bip39-gpu generate --words 24
        bip39-gpu generate --count 5 --json
    """
    word_count = int(words)

    try:
        for i in range(count):
            mnemonic = BIP39Mnemonic.generate(word_count)
            entropy_bits = WORDS_TO_ENTROPY_BITS[word_count]

            if count > 1 and not output_json:
                click.echo(f"\n=== Mnemonic {i + 1}/{count} ===")

            output = format_mnemonic_info(
                mnemonic,
                valid=True,
                entropy_bits=entropy_bits,
                as_json=output_json
            )
            click.echo(output)

            if count > 1 and not output_json:
                click.echo()

    except Exception as e:
        click.echo(error_message(str(e), as_json=output_json), err=True)
        raise click.Abort()
