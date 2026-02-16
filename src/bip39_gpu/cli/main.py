"""Main CLI entry point for bip39-gpu."""

import click
from ..__version__ import __version__
from .commands import generate, validate, seed, address, bruteforce


@click.group()
@click.version_option(version=__version__, prog_name="bip39-gpu")
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output"
)
def cli(verbose: bool) -> None:
    """BIP39 GPU - GPU-accelerated BIP39 mnemonic generator.

    A tool for generating, validating, and converting BIP39 mnemonic phrases
    with optional GPU acceleration via OpenCL.

    Examples:
        bip39-gpu generate --words 12
        bip39-gpu validate "word1 word2 ... word12"
        bip39-gpu seed "mnemonic phrase" --passphrase "test"
        bip39-gpu address "mnemonic phrase" --format Bech32 --count 5

    For more information, visit: https://github.com/young-developer/BIP39-GPU
    """
    if verbose:
        click.echo(f"bip39-gpu version {__version__}")


# Register commands
cli.add_command(generate)
cli.add_command(validate)
cli.add_command(seed)
cli.add_command(address)
cli.add_command(bruteforce)


if __name__ == "__main__":
    cli()
