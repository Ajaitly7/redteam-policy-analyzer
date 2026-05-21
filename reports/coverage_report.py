"""
reports/coverage_report.py
--------------------------
Generates a terminal coverage report using rich tables.

Shows:
  1. Pipeline summary  — prompt counts, classification breakdown
  2. Domain breakdown  — per-harm-category coverage matrix
  3. Top policy gaps   — worst-covered attack vectors
  4. Gold set summary  — label + confidence composition
  5. Most-bypassed framing pattern — which variation type most
     frequently produced UNSAFE classifications

Usage
-----
    from reports.coverage_report import print_coverage_report
    from database.connection import DatabaseConnection

    with DatabaseConnection() as db:
        print_coverage_report(db)
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.connection import DatabaseConnection
from core.coverage_mapper import CoverageMapper
from core.gold_set import GoldSetConstructor

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


console = Console() if RICH_AVAILABLE else None

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}

STATUS_COLOR = {
    "GAP": "bold red",
    "PARTIAL": "yellow",
    "COVERED": "green",
}

LABEL_COLOR = {
    "UNSAFE": "bold red",
    "AMBIGUOUS": "yellow",
    "SAFE": "green",
}


def _plain_print(title: str, rows: list, headers: list) -> None:
    """Fallback plain-text printer when rich is not available."""
    print(f"\n=== {title} ===")
    print("  ".join(f"{h:<20}" for h in headers))
    print("-" * (22 * len(headers)))
    for row in rows:
        print("  ".join(f"{str(v):<20}" for v in row))


def print_pipeline_summary(db: DatabaseConnection) -> None:
    total_prompts  = db.fetchone("SELECT COUNT(*) as c FROM prompts")["c"]
    base_prompts   = db.fetchone("SELECT COUNT(*) as c FROM prompts WHERE is_base=1")["c"]
    variations     = total_prompts - base_prompts
    classified     = db.fetchone("SELECT COUNT(*) as c FROM safety_classifications")["c"]
    unsafe_count   = db.fetchone("SELECT COUNT(*) as c FROM safety_classifications WHERE classification='UNSAFE'")["c"]
    ambig_count    = db.fetchone("SELECT COUNT(*) as c FROM safety_classifications WHERE classification='AMBIGUOUS'")["c"]
    safe_count     = db.fetchone("SELECT COUNT(*) as c FROM safety_classifications WHERE classification='SAFE'")["c"]
    gold_count     = db.fetchone("SELECT COUNT(*) as c FROM gold_set")["c"]

    if RICH_AVAILABLE:
        t = Table(title="Pipeline Summary", box=box.ROUNDED, show_header=True)
        t.add_column("Metric", style="bold cyan")
        t.add_column("Count", justify="right")
        t.add_row("Base prompts",    str(base_prompts))
        t.add_row("Variations",      str(variations))
        t.add_row("Total prompts",   str(total_prompts))
        t.add_row("Classified",      str(classified))
        t.add_row("UNSAFE",          Text(str(unsafe_count), style="bold red"))
        t.add_row("AMBIGUOUS",       Text(str(ambig_count),  style="yellow"))
        t.add_row("SAFE",            Text(str(safe_count),   style="green"))
        t.add_row("Gold set entries",str(gold_count))
        console.print(t)
    else:
        _plain_print("Pipeline Summary",
            [("Base prompts", base_prompts), ("Variations", variations),
             ("Classified", classified), ("UNSAFE", unsafe_count),
             ("AMBIGUOUS", ambig_count), ("SAFE", safe_count),
             ("Gold set", gold_count)],
            ["Metric", "Count"])


def print_domain_breakdown(db: DatabaseConnection) -> None:
    mapper = CoverageMapper()
    breakdown = mapper.domain_breakdown(db)

    if RICH_AVAILABLE:
        t = Table(title="Coverage by Harm Domain", box=box.ROUNDED)
        t.add_column("Domain",   style="bold")
        t.add_column("Severity")
        t.add_column("Vectors",  justify="right")
        t.add_column("Covered",  justify="right", style="green")
        t.add_column("Partial",  justify="right", style="yellow")
        t.add_column("Gap",      justify="right", style="bold red")
        for row in breakdown:
            sev_color = SEVERITY_COLOR.get(row["severity_level"], "white")
            t.add_row(
                row["harm_category"],
                Text(row["severity_level"], style=sev_color),
                str(row["total_vectors"] or 0),
                str(row["covered"] or 0),
                str(row["partial"] or 0),
                str(row["gap"] or 0),
            )
        console.print(t)
    else:
        _plain_print("Coverage by Harm Domain",
            [(r["harm_category"], r["severity_level"],
              r["total_vectors"], r["covered"], r["partial"], r["gap"])
             for r in breakdown],
            ["Domain", "Severity", "Vectors", "Covered", "Partial", "Gap"])


def print_top_gaps(db: DatabaseConnection, top_n: int = 8) -> None:
    sql = """
    SELECT
        av.name                  AS vector,
        hc.name                  AS category,
        hc.severity_level,
        pc.notes
    FROM policy_coverage pc
    JOIN attack_vectors av ON av.id = pc.attack_vector_id
    JOIN harm_categories hc ON hc.id = av.harm_category_id
    WHERE pc.coverage_status = 'GAP'
    ORDER BY
        CASE hc.severity_level
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH'     THEN 2
            WHEN 'MEDIUM'   THEN 3
            ELSE 4 END,
        av.name
    LIMIT ?
    """
    rows = db.fetchall(sql, (top_n,))

    if not rows:
        if RICH_AVAILABLE:
            console.print(Panel("[green]No policy gaps detected.[/green]", title="Policy Gaps"))
        else:
            print("\n=== Policy Gaps ===\nNo gaps detected.")
        return

    if RICH_AVAILABLE:
        t = Table(title=f"Top {top_n} Policy Gaps (by severity)", box=box.ROUNDED)
        t.add_column("Attack Vector",  style="bold")
        t.add_column("Category")
        t.add_column("Severity")
        t.add_column("Notes", max_width=60)
        for row in rows:
            sev_color = SEVERITY_COLOR.get(row["severity_level"], "white")
            t.add_row(
                row["vector"],
                row["category"],
                Text(row["severity_level"], style=sev_color),
                row["notes"] or "",
            )
        console.print(t)
    else:
        _plain_print("Top Policy Gaps",
            [(r["vector"], r["category"], r["severity_level"]) for r in rows],
            ["Vector", "Category", "Severity"])


def print_bypass_pattern_analysis(db: DatabaseConnection) -> None:
    """Show which jailbreak variation type most frequently produced UNSAFE."""
    sql = """
    SELECT
        p.variation_type,
        COUNT(*) AS total,
        SUM(CASE WHEN sc.classification = 'UNSAFE' THEN 1 ELSE 0 END) AS unsafe_count
    FROM prompts p
    JOIN safety_classifications sc ON sc.prompt_id = p.id
    WHERE p.is_base = 0 AND p.variation_type IS NOT NULL
    GROUP BY p.variation_type
    ORDER BY unsafe_count DESC
    """
    rows = db.fetchall(sql)

    if RICH_AVAILABLE:
        t = Table(title="Bypass Pattern Analysis", box=box.ROUNDED)
        t.add_column("Variation Type",  style="bold cyan")
        t.add_column("Total",           justify="right")
        t.add_column("UNSAFE",          justify="right", style="red")
        t.add_column("UNSAFE Rate",     justify="right")
        for row in rows:
            rate = (row["unsafe_count"] / row["total"] * 100) if row["total"] > 0 else 0
            rate_str = f"{rate:.0f}%"
            rate_style = "bold red" if rate > 40 else "yellow" if rate > 20 else "green"
            t.add_row(
                row["variation_type"] or "—",
                str(row["total"]),
                str(row["unsafe_count"]),
                Text(rate_str, style=rate_style),
            )
        console.print(t)
    else:
        _plain_print("Bypass Pattern Analysis",
            [(r["variation_type"], r["total"], r["unsafe_count"]) for r in rows],
            ["Variation Type", "Total", "UNSAFE"])


def print_gold_set_summary(db: DatabaseConnection) -> None:
    gs = GoldSetConstructor()
    summary = gs.summary(db)

    if RICH_AVAILABLE:
        t = Table(title="Gold Set Composition", box=box.ROUNDED)
        t.add_column("Label",      style="bold")
        t.add_column("HIGH",       justify="right", style="green")
        t.add_column("MEDIUM",     justify="right", style="yellow")
        t.add_column("LOW",        justify="right", style="red")
        t.add_column("Total",      justify="right")
        for label in ["UNSAFE", "AMBIGUOUS", "SAFE"]:
            counts = summary.get(label, {})
            h = counts.get("HIGH", 0)
            m = counts.get("MEDIUM", 0)
            l = counts.get("LOW", 0)
            color = LABEL_COLOR.get(label, "white")
            t.add_row(Text(label, style=color), str(h), str(m), str(l), str(h+m+l))
        console.print(t)
    else:
        _plain_print("Gold Set Composition",
            [(lbl, summary.get(lbl, {}).get("HIGH", 0),
              summary.get(lbl, {}).get("MEDIUM", 0),
              summary.get(lbl, {}).get("LOW", 0))
             for lbl in ["UNSAFE", "AMBIGUOUS", "SAFE"]],
            ["Label", "HIGH", "MEDIUM", "LOW"])


def print_coverage_report(db: DatabaseConnection) -> None:
    """Print the full pipeline coverage report."""
    if RICH_AVAILABLE:
        console.rule("[bold cyan]Red-Team Policy Coverage Report[/bold cyan]")

    print_pipeline_summary(db)
    print_domain_breakdown(db)
    print_top_gaps(db)
    print_bypass_pattern_analysis(db)
    print_gold_set_summary(db)

    if RICH_AVAILABLE:
        console.rule()
