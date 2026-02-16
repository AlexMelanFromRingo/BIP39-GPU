"""Seed command - convert mnemonic to seed."""

import click
from ...core.mnemonic import BIP39Mnemonic
from ...core.pbkdf2_batch import batch_mnemonic_to_seed, estimate_batch_time
from ..utils import error_message
import time


@click.command()
@click.argument("mnemonic", required=False)
@click.option(
    "-p", "--passphrase",
    default="",
    help="BIP39 passphrase (default: empty)"
)
@click.option(
    "--base64",
    is_flag=True,
    help="Output seed as base64 instead of hex"
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON"
)
@click.option(
    "--gpu",
    is_flag=True,
    help="Use GPU acceleration (PBKDF2-HMAC-SHA512, auto-fallback to CPU)"
)
@click.option(
    "-f", "--file",
    "input_file",
    type=click.File("r"),
    help="Read mnemonics from file (one per line)"
)
@click.option(
    "--batch",
    is_flag=True,
    help="Batch mode: process multiple mnemonics from file"
)
def seed(
    mnemonic: str,
    passphrase: str,
    base64: bool,
    output_json: bool,
    gpu: bool,
    input_file,
    batch: bool
) -> None:
    """Convert mnemonic to BIP39 seed.

    MNEMONIC should be a space-separated list of words.

    Examples:
        bip39-gpu seed "word1 word2 ... word12"
        bip39-gpu seed "mnemonic..." --passphrase "secret"
        bip39-gpu seed "mnemonic..." --base64
        bip39-gpu seed --file mnemonics.txt --batch
        bip39-gpu seed "mnemonic..." --gpu
    """
    try:
        # Batch mode from file
        if batch or input_file:
            if not input_file:
                raise click.UsageError("--batch requires --file option")

            mnemonics = [line.strip() for line in input_file if line.strip()]

            if not mnemonics:
                click.echo("No mnemonics found in file", err=True)
                return

            # Show progress
            click.echo(f"Processing {len(mnemonics)} mnemonic(s)...")
            estimated = estimate_batch_time(len(mnemonics))
            click.echo(f"Estimated time: {estimated}")

            start = time.time()

            # Batch processing
            passphrases = [passphrase] * len(mnemonics)
            seeds = batch_mnemonic_to_seed(mnemonics, passphrases, use_gpu=gpu)

            elapsed = time.time() - start

            # Output results
            if output_json:
                import json
                results = []
                for i, (m, s) in enumerate(zip(mnemonics, seeds)):
                    results.append({
                        "index": i,
                        "mnemonic": m[:30] + "..." if len(m) > 30 else m,
                        "seed": s.hex() if not base64 else __import__('base64').b64encode(s).decode(),
                    })
                data = {
                    "count": len(seeds),
                    "elapsed_seconds": elapsed,
                    "results": results
                }
                click.echo(json.dumps(data, indent=2))
            else:
                click.echo(f"\nGenerated {len(seeds)} seed(s) in {elapsed:.2f}s")
                click.echo(f"Average: {elapsed/len(seeds)*1000:.2f}ms per seed\n")

                for i, (m, s) in enumerate(zip(mnemonics, seeds)):
                    click.echo(f"[{i}] {m[:40]}...")
                    if base64:
                        import base64 as b64
                        click.echo(f"    Seed: {b64.b64encode(s).decode()}")
                    else:
                        click.echo(f"    Seed: {s.hex()}")

            return

        # Single mnemonic mode
        if not mnemonic:
            raise click.UsageError("MNEMONIC argument required (or use --file for batch)")

        # Validate mnemonic
        if not BIP39Mnemonic.validate(mnemonic):
            click.echo(
                error_message("Invalid mnemonic (checksum failed)", as_json=output_json),
                err=True
            )
            raise click.Abort()

        # Convert to seed
        if gpu:
            import warnings
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                seeds = batch_mnemonic_to_seed([mnemonic], [passphrase], use_gpu=True)
                if w:
                    click.echo(f"Warning: {w[0].message}", err=True)
            seed_bytes = seeds[0]
        else:
            seed_bytes = BIP39Mnemonic.to_seed(mnemonic, passphrase=passphrase)

        # Format output
        if base64:
            import base64 as b64
            seed_str = b64.b64encode(seed_bytes).decode()
        else:
            seed_str = seed_bytes.hex()

        # Output
        if output_json:
            import json
            data = {
                "mnemonic": mnemonic,
                "seed": seed_str,
                "length": len(seed_bytes),
                "encoding": "base64" if base64 else "hex"
            }
            click.echo(json.dumps(data, indent=2))
        else:
            click.echo(f"Seed ({len(seed_bytes)} bytes):")
            click.echo(seed_str)

    except Exception as e:
        click.echo(error_message(str(e), as_json=output_json), err=True)
        raise click.Abort()
