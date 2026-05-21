"""
cli.py
------
Top-level CLI wiring all pipeline stages.

Commands
--------
    python cli.py seed       — Load harm taxonomy + 45 base prompts
    python cli.py generate   — Run variation generator (5 transforms × base prompts)
    python cli.py classify   — Run heuristic safety classifier on all unclassified prompts
    python cli.py coverage   — Run coverage mapper and persist gap analysis
    python cli.py goldset    — Auto-select gold set + export to gold_set.csv
    python cli.py report     — Print full coverage report
    python cli.py reset      — Drop and re-seed the database (dev utility)
    python cli.py status     — Quick counts of all tables
"""

import sys
import click
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.connection import DatabaseConnection, DEFAULT_DB_PATH
from data.seed_prompts import seed
from core.variation_generator import VariationGenerator
from core.classifier import HeuristicClassifier
from core.coverage_mapper import CoverageMapper
from core.gold_set import GoldSetConstructor
from reports.coverage_report import print_coverage_report


@click.group()
@click.option("--db", default=str(DEFAULT_DB_PATH), help="Path to SQLite database")
@click.pass_context
def cli(ctx, db):
    """Red-Team Policy Analyzer — adversarial prompt dataset and policy gap pipeline."""
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = Path(db)


# ── seed ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--fresh", is_flag=True, default=False,
              help="Drop existing DB and re-seed from scratch")
@click.pass_context
def seed_cmd(ctx, fresh):
    """Load harm taxonomy, attack vectors, policy rules, and 45 base prompts."""
    db_path = ctx.obj["db_path"]
    if fresh and db_path.exists():
        db_path.unlink()
        click.echo(f"Removed existing DB: {db_path}")
    with DatabaseConnection(db_path) as db:
        seed(db)


cli.add_command(seed_cmd, name="seed")


# ── generate ──────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def generate(ctx):
    """Generate adversarial variations for all base prompts (5 transforms each)."""
    db_path = ctx.obj["db_path"]
    with DatabaseConnection(db_path) as db:
        gen = VariationGenerator()
        count = gen.generate_all(db)
        stats = gen.stats(db)
    click.echo(f"Generated {count} new variations.")
    for vtype, n in sorted(stats.items()):
        click.echo(f"  {vtype:<22} {n}")


# ── classify ──────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def classify(ctx):
    """Run heuristic safety classifier on all unclassified prompts."""
    db_path = ctx.obj["db_path"]
    with DatabaseConnection(db_path) as db:
        clf = HeuristicClassifier()
        count = clf.classify_all(db)
        summary = clf.summary(db)
    click.echo(f"Classified {count} prompts.")
    for label, n in sorted(summary.items()):
        click.echo(f"  {label:<12} {n}")


# ── coverage ──────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def coverage(ctx):
    """Map policy coverage gaps across attack vectors."""
    db_path = ctx.obj["db_path"]
    with DatabaseConnection(db_path) as db:
        mapper = CoverageMapper()
        results = mapper.map_all(db)
        summary = mapper.coverage_summary(db)
        gaps = mapper.get_gaps(db)
    click.echo(f"Coverage analysis complete: {len(results)} vectors evaluated.")
    for status, n in sorted(summary.items()):
        click.echo(f"  {status:<10} {n}")
    if gaps:
        click.echo(f"\n{len(gaps)} GAP vector(s) requiring policy attention:")
        for g in gaps:
            click.echo(f"  [{g['harm_category']}] {g['vector_name']}")


# ── goldset ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--export", default="gold_set.csv", show_default=True,
              help="Output CSV file path")
@click.pass_context
def goldset(ctx, export):
    """Auto-select gold set entries and export to CSV."""
    db_path = ctx.obj["db_path"]
    with DatabaseConnection(db_path) as db:
        gs = GoldSetConstructor()
        counts = gs.auto_select(db)
        rows = gs.export_csv(db, export)
        review_items = gs.get_for_review(db)

    total = sum(counts.values())
    click.echo(f"Gold set: {total} entries selected.")
    for label, n in sorted(counts.items()):
        click.echo(f"  {label:<12} {n}")
    click.echo(f"\nExported {rows} rows to {export}")
    if review_items:
        click.echo(
            f"\n{len(review_items)} entries flagged for human review "
            f"(AMBIGUOUS or LOW confidence) — see gold_set.csv"
        )


# ── report ────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def report(ctx):
    """Print the full policy coverage report."""
    db_path = ctx.obj["db_path"]
    with DatabaseConnection(db_path) as db:
        print_coverage_report(db)


# ── status ────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def status(ctx):
    """Show current row counts for all tables."""
    db_path = ctx.obj["db_path"]
    tables = [
        "harm_categories", "attack_vectors", "policy_rules",
        "prompts", "model_responses", "safety_classifications",
        "policy_coverage", "gold_set",
    ]
    with DatabaseConnection(db_path) as db:
        click.echo(f"Database: {db_path}")
        for table in tables:
            row = db.fetchone(f"SELECT COUNT(*) as c FROM {table}")
            click.echo(f"  {table:<28} {row['c']}")


# ── reset ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.confirmation_option(prompt="This will delete all data. Are you sure?")
@click.pass_context
def reset(ctx):
    """Drop and re-seed the database."""
    db_path = ctx.obj["db_path"]
    if db_path.exists():
        db_path.unlink()
        click.echo(f"Removed: {db_path}")
    with DatabaseConnection(db_path) as db:
        seed(db)
    click.echo("Database reset complete.")


if __name__ == "__main__":
    cli()
