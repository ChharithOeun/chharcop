"""CLI entry point for Chharcop."""

import asyncio
import json

import click
from loguru import logger

from chharcop import Chharcop
from chharcop.models import ScanResult


@click.group()
@click.version_option(version="0.1.0", prog_name="chharcop")
def cli() -> None:
    """Chharcop: Cross-platform scam evidence collection and reporting toolkit."""
    logger.enable("chharcop")


@cli.command()
@click.argument("url")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def website(url: str, output_json: bool) -> None:
    """Scan a website for evidence and indicators."""

    async def scan() -> None:
        chharcop = Chharcop()
        result = await chharcop.scan_website(url)

        if output_json:
            click.echo(result.model_dump_json(indent=2))
        else:
            click.echo(f"Website Scan Results: {url}")
            click.echo(f"Risk Level: {result.risk_level}")
            click.echo(f"Risk Score: {result.risk_score:.2f}")
            if result.risk_factors:
                click.echo(f"Risk Factors: {', '.join(result.risk_factors)}")

    asyncio.run(scan())


@cli.command()
@click.argument("steam_id")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def steam(steam_id: str, output_json: bool) -> None:
    """Scan a Steam gaming profile."""

    async def scan() -> None:
        chharcop = Chharcop()
        result = await chharcop.scan_steam(steam_id)

        if output_json:
            click.echo(result.model_dump_json(indent=2))
        else:
            click.echo(f"Steam Scan Results: {steam_id}")
            click.echo(f"Risk Level: {result.risk_level}")
            click.echo(f"Risk Score: {result.risk_score:.2f}")

    asyncio.run(scan())


@cli.command()
@click.argument("user_id")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def discord(user_id: str, output_json: bool) -> None:
    """Scan a Discord user account."""

    async def scan() -> None:
        chharcop = Chharcop()
        result = await chharcop.scan_discord(user_id)

        if output_json:
            click.echo(result.model_dump_json(indent=2))
        else:
            click.echo(f"Discord Scan Results: {user_id}")
            click.echo(f"Risk Level: {result.risk_level}")

    asyncio.run(scan())


@cli.command()
@click.argument("username")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def gamertag(username: str, output_json: bool) -> None:
    """Search gamertag across gaming platforms."""

    async def scan() -> None:
        chharcop = Chharcop()
        result = await chharcop.scan_gamertag(username)

        if output_json:
            click.echo(result.model_dump_json(indent=2))
        else:
            click.echo(f"Gamertag OSINT Results: {username}")

    asyncio.run(scan())


@cli.command()
@click.argument("target")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def scan(target: str, output_json: bool) -> None:
    """Auto-detect target type and run appropriate scan."""

    async def run_scan() -> None:
        chharcop = Chharcop()
        results = await chharcop.full_scan(target)

        if isinstance(results, list):
            for result in results:
                if output_json:
                    click.echo(result.model_dump_json(indent=2))
                else:
                    click.echo(f"Scan Results: {target}")
                    click.echo(f"Type: {result.scan_type}")
                    click.echo(f"Risk Level: {result.risk_level}")
        else:
            if output_json:
                click.echo(results.model_dump_json(indent=2))
            else:
                click.echo(f"Scan Results: {target}")
                click.echo(f"Type: {results.scan_type}")
                click.echo(f"Risk Level: {results.risk_level}")

    asyncio.run(run_scan())


if __name__ == "__main__":
    cli()
