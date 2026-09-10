"""Render a framework markdown doc to PDF + DOCX.

PDF uses the two-stage pipeline (pandoc -> HTML -> Chrome headless) that
avoids macOS's SIP-blocked weasyprint. DOCX uses pandoc directly.

Used by Phase 1..7 to produce the versioned deliverables under output/.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
       max-width: 780px; margin: 2em auto; padding: 0 1.5em; line-height: 1.5;
       color: #1a1a1a; }
h1 { font-size: 24pt; border-bottom: 2px solid #333; padding-bottom: 0.3em; }
h2 { font-size: 18pt; margin-top: 1.6em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }
h3 { font-size: 14pt; margin-top: 1.4em; color: #333; }
h4 { font-size: 12pt; margin-top: 1.2em; color: #555; }
code { background: #f4f4f4; padding: 0.1em 0.3em; border-radius: 3px;
       font-family: 'SF Mono', Menlo, Monaco, monospace; font-size: 90%; }
pre { background: #f4f4f4; padding: 1em; border-radius: 4px; overflow-x: auto;
      font-size: 88%; line-height: 1.35; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; margin: 1em 0; width: 100%; font-size: 96%; }
th, td { border: 1px solid #bbb; padding: 0.4em 0.7em; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
blockquote { border-left: 4px solid #888; margin: 1em 0; padding: 0.4em 1em;
             color: #555; background: #f8f8f8; }
hr { border: none; border-top: 1px solid #ccc; margin: 2em 0; }
"""


def _sanitize_body(md: str) -> str:
    """Pandoc can misread `---` lines as YAML block boundaries — swap for em-dash."""
    lines = md.splitlines()
    out = []
    for i, line in enumerate(lines):
        if line.strip() == "---" and 0 < i < len(lines) - 1:
            out.append("—" * 40)
        else:
            out.append(line)
    return "\n".join(out)


def render(md_path: Path, pdf_out: Path, docx_out: Path) -> None:
    md_path = md_path.resolve()
    pdf_out = pdf_out.resolve()
    docx_out = docx_out.resolve()
    pdf_out.parent.mkdir(parents=True, exist_ok=True)
    docx_out.parent.mkdir(parents=True, exist_ok=True)

    text = md_path.read_text(encoding="utf-8")
    clean = _sanitize_body(text)
    tmp_md = md_path.with_suffix(".sanitised.md")
    tmp_md.write_text(clean, encoding="utf-8")

    tmp_html = md_path.with_suffix(".html")
    tmp_css = md_path.with_suffix(".css")
    tmp_css.write_text(CSS, encoding="utf-8")

    console.print(f"[bold]Rendering PDF[/] via pandoc + Chrome …")
    subprocess.run(
        ["pandoc", str(tmp_md),
         "-f", "gfm+pipe_tables+task_lists",
         "-t", "html5",
         "--standalone",
         "-c", tmp_css.name,
         "-o", str(tmp_html)],
        check=True,
    )
    subprocess.run(
        [CHROME, "--headless", "--disable-gpu", "--no-pdf-header-footer",
         f"--print-to-pdf={pdf_out}", tmp_html.as_uri()],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    console.print(f"[bold]Rendering DOCX[/] via pandoc …")
    subprocess.run(
        ["pandoc", str(tmp_md),
         "-f", "gfm+pipe_tables+task_lists",
         "-t", "docx",
         "-o", str(docx_out)],
        check=True,
    )

    # Cleanup temp files
    for p in (tmp_md, tmp_html, tmp_css):
        try:
            p.unlink()
        except OSError:
            pass

    console.print(f"  PDF:  [green]{pdf_out}[/]  ({pdf_out.stat().st_size:,} bytes)")
    console.print(f"  DOCX: [green]{docx_out}[/]  ({docx_out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("usage: python -m framework.render_doc <input.md> <output.pdf> <output.docx>")
        sys.exit(2)
    render(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
