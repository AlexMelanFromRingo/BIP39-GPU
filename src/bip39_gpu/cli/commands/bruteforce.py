"""Bruteforce command - recover partial mnemonics."""

import click
import time
from ...bruteforce import BruteForceSearch
from ..utils import error_message, success_message


@click.command()
@click.option(
    "-p", "--pattern",
    required=True,
    help='Mnemonic pattern with ??? for unknown words (e.g., "word1 ??? word3 ???")'
)
@click.option(
    "--target",
    help="Optional target Bitcoin address to match"
)
@click.option(
    "--max-results",
    type=int,
    default=1,
    help="Maximum number of results to find (default: 1)"
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Estimate feasibility without performing search"
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON"
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Verbose output with progress"
)
def bruteforce(
    pattern: str,
    target: str,
    max_results: int,
    dry_run: bool,
    output_json: bool,
    verbose: bool
) -> None:
    """Brute-force recover partial mnemonics.

    Use ??? to mark unknown words in the pattern.

    Examples:
        # Recover 1 unknown word
        bip39-gpu bruteforce --pattern "abandon ??? about"

        # Recover 2 unknown words (may take time)
        bip39-gpu bruteforce --pattern "abandon ??? ??? ... about"

        # Check feasibility first
        bip39-gpu bruteforce --pattern "word1 ??? ??? word4 ..." --dry-run

        # Search for specific address
        bip39-gpu bruteforce --pattern "word1 ??? word3" --target 1A1zP1...
    """
    try:
        # Create search instance
        search = BruteForceSearch(pattern)

        # Dry run - just show estimates
        if dry_run:
            stats = search.estimate_feasibility()

            if output_json:
                import json
                click.echo(json.dumps(stats, indent=2))
            else:
                click.echo("\n=== Brute-Force Feasibility Analysis ===\n")
                click.echo(f"Pattern:         {stats['pattern']}")
                click.echo(f"Word count:      {stats['word_count']}")
                click.echo(f"Unknown words:   {stats['unknown_words']}")
                click.echo(f"Search space:    {stats['search_space']:,} combinations")
                click.echo(f"Estimated time:  {stats['estimated_time']}")
                click.echo(f"Feasible:        {'Yes' if stats['feasible'] else 'No'}")
                click.echo(f"\n{stats['recommendation']}\n")

            return

        # Actual search
        stats = search.estimate_feasibility()

        # Warn if not feasible
        if not stats['feasible']:
            click.echo(
                click.style(
                    f"\n⚠️  Warning: Large search space ({stats['search_space']:,} combinations)\n"
                    f"   Estimated time: {stats['estimated_time']}\n"
                    f"   Consider reducing unknown words to 3 or less.\n",
                    fg="yellow"
                ),
                err=True
            )

            if not click.confirm("Continue anyway?"):
                raise click.Abort()

        if verbose:
            click.echo(f"\nSearching {stats['search_space']:,} combinations...")
            click.echo(f"Pattern: {stats['pattern']}\n")

        # Progress tracking
        start_time = time.time()
        last_progress = [0]

        def progress_callback(current: int, total: int):
            if verbose and current % 10000 == 0:
                elapsed = time.time() - start_time
                rate = current / elapsed if elapsed > 0 else 0
                eta = (total - current) / rate if rate > 0 else 0

                click.echo(
                    f"\rProgress: {current:,}/{total:,} ({current/total*100:.1f}%) "
                    f"| Rate: {rate:,.0f}/s | ETA: {eta:.1f}s",
                    nl=False
                )
                last_progress[0] = current

        # Perform search
        results = search.search(
            validate_only=(target is None),
            target_address=target,
            progress_callback=progress_callback if verbose else None,
            max_results=max_results,
        )

        elapsed = time.time() - start_time

        if verbose and last_progress[0] > 0:
            click.echo()  # New line after progress

        # Output results
        if output_json:
            import json
            data = {
                "pattern": pattern,
                "search_space": stats['search_space'],
                "found": len(results),
                "results": results,
                "elapsed_seconds": elapsed,
            }
            click.echo(json.dumps(data, indent=2))
        else:
            click.echo(f"\n=== Search Complete ===\n")
            click.echo(f"Elapsed time: {elapsed:.2f}s")
            click.echo(f"Found: {len(results)} mnemonic(s)\n")

            if results:
                for i, mnemonic in enumerate(results, 1):
                    click.echo(f"Result {i}:")
                    click.echo(f"  {mnemonic}\n")

                click.echo(click.style("✅ Success!", fg="green"))
            else:
                click.echo(click.style("❌ No valid mnemonics found", fg="red"))

    except ValueError as e:
        click.echo(error_message(str(e), as_json=output_json), err=True)
        raise click.Abort()

    except KeyboardInterrupt:
        click.echo("\n\nSearch interrupted by user.", err=True)
        raise click.Abort()

    except Exception as e:
        click.echo(error_message(f"Search failed: {e}", as_json=output_json), err=True)
        raise click.Abort()
