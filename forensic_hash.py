#!/usr/bin/env python3
"""Forensic Hash Tool — cryptographic integrity verification for digital evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import platform
import socket
import sys
from datetime import datetime
from pathlib import Path

SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
BUFFER_SIZE = 65536


def _format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def _format_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size_bytes} B"


def calculate_hashes(filepath: str | Path, algorithms: list[str]) -> dict[str, str]:
    """Read a file once and compute all requested hashes."""
    path = Path(filepath)
    hashers = {algo: hashlib.new(algo) for algo in algorithms}

    try:
        with path.open("rb") as handle:
            while chunk := handle.read(BUFFER_SIZE):
                for hasher in hashers.values():
                    hasher.update(chunk)
    except PermissionError:
        return {algo: "ERR:PERMISSION_DENIED" for algo in algorithms}
    except OSError as exc:
        return {algo: f"ERR:{exc.__class__.__name__.upper()}" for algo in algorithms}

    return {algo: hashers[algo].hexdigest() for algo in algorithms}


def get_file_metadata(filepath: str | Path) -> dict:
    """Collect filesystem metadata for a single file."""
    path = Path(filepath)
    stat = path.stat()

    return {
        "size_bytes": stat.st_size,
        "size_human": _format_size(stat.st_size),
        "created": _format_timestamp(stat.st_ctime),
        "modified": _format_timestamp(stat.st_mtime),
        "accessed": _format_timestamp(stat.st_atime),
        "extension": path.suffix.lower() if path.suffix else "",
    }


def _process_file(filepath: str | Path, algorithms: list[str]) -> dict:
    path = Path(filepath)
    return {
        "path": str(path.resolve()),
        "meta": get_file_metadata(path),
        "hashes": calculate_hashes(path, algorithms),
    }


def scan_target(target: str | Path, recursive: bool, algorithms: list[str]) -> list[dict]:
    """Scan a file or directory and return processed results."""
    path = Path(target)

    if not path.exists():
        raise FileNotFoundError(f"Target not found: {path}")

    if path.is_file():
        return [_process_file(path, algorithms)]

    pattern = "**/*" if recursive else "*"
    results: list[dict] = []

    for candidate in sorted(path.glob(pattern)):
        if candidate.is_file():
            results.append(_process_file(candidate, algorithms))

    return results


def build_report(results: list[dict], target: str | Path, algorithms: list[str], examiner: str | None = None) -> dict:
    """Build the top-level report object."""
    report_metadata = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "os": platform.platform(),
        "target": str(Path(target).resolve()),
        "algorithms": algorithms,
        "total_files": len(results),
    }
    if examiner:
        report_metadata["examiner"] = examiner

    return {
        "report_metadata": report_metadata,
        "files": results,
    }


def render_text_report(report: dict) -> str:
    """Render a human-readable forensic text report."""
    meta = report["report_metadata"]
    lines = [
        "=" * 72,
        "FORENSIC HASH INTEGRITY REPORT",
        "=" * 72,
        f"Generated   : {meta['generated']}",
    ]
    if meta.get("examiner"):
        lines.append(f"Examiner    : \"{meta['examiner']}\"")
    lines.extend(
        [
            f"OS          : {meta['os']}",
            f"Target      : {meta['target']}",
            f"Algorithms  : {', '.join(meta['algorithms']).upper()}",
            f"Total Files : {meta['total_files']}",
            "=" * 72,
            "",
        ]
    )

    for index, entry in enumerate(report["files"], start=1):
        file_meta = entry["meta"]
        lines.extend(
            [
                f"[{index}] {entry['path']}",
                f"    Dosya Adı  : {Path(entry['path']).name}",
                f"    Size      : {file_meta['size_human']} ({file_meta['size_bytes']} bytes)",
                f"    Extension : {file_meta['extension'] or '(none)'}",
                f"    Created   : {file_meta['created']}",
                f"    Modified  : {file_meta['modified']}",
                f"    Accessed  : {file_meta['accessed']}",
            ]
        )
        for algo in meta["algorithms"]:
            value = entry["hashes"].get(algo, "ERR:MISSING")
            lines.append(f"    {algo.upper():8}: {value}")
        lines.append("-" * 72)

    return "\n".join(lines)


def render_csv_report(report: dict) -> str:
    """Render report rows as CSV."""
    meta = report["report_metadata"]
    algorithms = meta["algorithms"]
    fieldnames = [
        "path",
        "filename",
        "size_bytes",
        "size_human",
        "extension",
        "created",
        "modified",
        "accessed",
        *algorithms,
    ]

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    for entry in report["files"]:
        file_meta = entry["meta"]
        row = {
            "path": entry["path"],
            "filename": Path(entry["path"]).name,
            "size_bytes": file_meta["size_bytes"],
            "size_human": file_meta["size_human"],
            "extension": file_meta["extension"],
            "created": file_meta["created"],
            "modified": file_meta["modified"],
            "accessed": file_meta["accessed"],
        }
        for algo in algorithms:
            row[algo] = entry["hashes"].get(algo, "")
        writer.writerow(row)

    return buffer.getvalue()


def write_pdf_report(report: dict, output_path: str | Path) -> None:
    """Write a styled PDF report. Requires reportlab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError as exc:
        raise ValueError(
            "PDF export requires reportlab. Install with: pip install reportlab"
        ) from exc

    meta = report["report_metadata"]
    algorithms = meta["algorithms"]
    path = Path(output_path)

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title="Forensic Hash Report",
    )

    unicode_font = "Helvetica"
    font_paths = [
        "C:\\Windows\\Fonts\\DejaVuSans.ttf",
        "C:\\Windows\\Fonts\\Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    for font_path in font_paths:
        if Path(font_path).exists():
            try:
                pdfmetrics.registerFont(TTFont("ReportFont", str(font_path)))
                unicode_font = "ReportFont"
                break
            except Exception:
                continue

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName=unicode_font,
        fontSize=20,
        textColor=colors.white,
        alignment=TA_CENTER,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName=unicode_font,
        fontSize=10,
        textColor=colors.HexColor("#dbeafe"),
        alignment=TA_CENTER,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName=unicode_font,
        fontSize=13,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName=unicode_font,
        fontSize=9,
        textColor=colors.HexColor("#1e293b"),
        leading=12,
    )
    hash_value_style = ParagraphStyle(
        "HashValue",
        parent=styles["Normal"],
        fontName=unicode_font,
        fontSize=8,
        textColor=colors.HexColor("#065f46"),
        leading=12,
    )

    story = []

    cover_data = [
        [Paragraph("FORENSIC HASH INTEGRITY REPORT", title_style)],
        [Paragraph("Chain of Custody · Delil Bütünlük Raporu", subtitle_style)],
    ]
    cover_table = Table(cover_data, colWidths=[17 * cm])
    cover_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1d4ed8")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#38bdf8")),
                ("TOPPADDING", (0, 0), (-1, -1), 18),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
            ]
        )
    )
    story.append(cover_table)
    story.append(Spacer(1, 0.5 * cm))

    summary_rows = [
        ["Alan", "Değer"],
        ["Oluşturulma", meta["generated"]],
    ]
    if meta.get("examiner"):
        summary_rows.append(["İnceleyen", f'"{meta["examiner"]}"'])
    summary_rows.extend(
        [
            ["Hedef", meta["target"]],
            ["Algoritmalar", ", ".join(algo.upper() for algo in algorithms)],
            ["Toplam Dosya", str(meta["total_files"])],
        ]
    )
    summary_table = Table(summary_rows, colWidths=[4.5 * cm, 12.5 * cm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), unicode_font),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.6 * cm))

    for index, entry in enumerate(report["files"], start=1):
        file_meta = entry["meta"]
        story.append(Paragraph(f"Dosya #{index}", section_style))
        story.append(Spacer(1, 0.15 * cm))

        meta_rows = [
            ["Dosya Adı", Path(entry["path"]).name],
            ["Dosya Yolu", entry["path"]],
            ["Boyut", f"{file_meta['size_human']} ({file_meta['size_bytes']} bytes)"],
            ["Uzantı", file_meta["extension"] or "(yok)"],
            ["Oluşturulma", file_meta["created"]],
            ["Değiştirilme", file_meta["modified"]],
            ["Erişim", file_meta["accessed"]],
        ]
        meta_table = Table(meta_rows, colWidths=[3.5 * cm, 13.5 * cm])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                    ("FONTNAME", (0, 0), (-1, -1), unicode_font),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 0.15 * cm))

        hash_rows = [["Algoritma", "Hash Değeri"]]
        for algo in algorithms:
            raw_hash = entry["hashes"].get(algo, "ERR:MISSING")
            if isinstance(raw_hash, str):
                wrapped_hash = "<br/>".join(raw_hash[i : i + 64] for i in range(0, len(raw_hash), 64))
                hash_rows.append([algo.upper(), Paragraph(wrapped_hash, hash_value_style)])
            else:
                hash_rows.append([algo.upper(), Paragraph(str(raw_hash), hash_value_style)])

        hash_table = Table(hash_rows, colWidths=[3 * cm, 14 * cm], repeatRows=1)
        hash_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, -1), unicode_font),
                    ("TEXTCOLOR", (1, 1), (1, -1), colors.HexColor("#065f46")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(hash_table)
        story.append(Spacer(1, 0.35 * cm))

    doc.build(story)


def _get_pdf_unicode_font() -> str:
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError as exc:
        raise ValueError(
            "PDF export requires reportlab. Install with: pip install reportlab"
        ) from exc

    unicode_font = "Helvetica"
    font_paths = [
        "C:\\Windows\\Fonts\\DejaVuSans.ttf",
        "C:\\Windows\\Fonts\\Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    for font_path in font_paths:
        if Path(font_path).exists():
            try:
                pdfmetrics.registerFont(TTFont("ReportFont", str(font_path)))
                unicode_font = "ReportFont"
                break
            except Exception:
                continue
    return unicode_font


def write_pdf_verification_report(report: dict, output_path: str | Path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise ValueError(
            "PDF export requires reportlab. Install with: pip install reportlab"
        ) from exc

    meta = report["report_metadata"]
    path = Path(output_path)

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title="Forensic Hash Verification Report",
    )

    unicode_font = _get_pdf_unicode_font()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName=unicode_font,
        fontSize=20,
        textColor=colors.white,
        alignment=TA_CENTER,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName=unicode_font,
        fontSize=10,
        textColor=colors.HexColor("#dbeafe"),
        alignment=TA_CENTER,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName=unicode_font,
        fontSize=13,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName=unicode_font,
        fontSize=9,
        textColor=colors.HexColor("#1e293b"),
        leading=12,
    )

    story = []

    cover_data = [
        [Paragraph("FORENSIC HASH VERIFICATION REPORT", title_style)],
        [Paragraph("Baseline comparison and integrity summary", subtitle_style)],
    ]
    cover_table = Table(cover_data, colWidths=[17 * cm])
    cover_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1d4ed8")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#38bdf8")),
                ("TOPPADDING", (0, 0), (-1, -1), 18),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
            ]
        )
    )
    story.append(cover_table)
    story.append(Spacer(1, 0.5 * cm))

    summary_rows = [
        ["Alan", "Değer"],
        ["Oluşturulma", meta["generated"]],
        ["Referans Baseline", meta.get("baseline", "")],
    ]
    if meta.get("examiner"):
        summary_rows.append(["İnceleyen", f'"{meta["examiner"]}"'])
    if meta.get("algorithms"):
        summary_rows.append(["Algoritmalar", ", ".join(algo.upper() for algo in meta["algorithms"])])
    summary_rows.append(["Toplam Dosya", str(meta["total_files"])])
    summary_table = Table(summary_rows, colWidths=[4.5 * cm, 12.5 * cm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), unicode_font),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.6 * cm))

    story.append(Paragraph("Dosya Durumları", section_style))
    status_rows = [["Durum", "Dosya Yolu"]]
    for entry in report["files"]:
        status_rows.append([
            Paragraph(entry["status"], body_style),
            Paragraph(html.escape(entry["path"]), body_style),
        ])

    status_table = Table(status_rows, colWidths=[3.5 * cm, 13.5 * cm])
    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), unicode_font),
                ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#065f46")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(status_table)
    story.append(Spacer(1, 0.4 * cm))

    for entry in report["files"]:
        if entry.get("diffs"):
            story.append(Paragraph(f"Değişiklikler: {entry['path']}", section_style))
            for diff in entry["diffs"]:
                story.append(Paragraph(f"{diff['algorithm'].upper()}: {diff['baseline']} → {diff['current']}", body_style))
            story.append(Spacer(1, 0.25 * cm))

    doc.build(story)


def verify_against(current_results: list[dict], baseline_path: str | Path) -> str:
    """Compare current scan results against a previous JSON baseline report."""
    # Keep legacy text output by delegating to the structured verifier
    struct = build_verification_struct(current_results, baseline_path)
    return render_text_verification(struct)


def build_verification_struct(
    current_results: list[dict],
    baseline_path: str | Path,
    algorithms: list[str] | None = None,
    examiner: str | None = None,
) -> dict:
    """Build a structured verification report usable by multiple renderers."""
    baseline_file = Path(baseline_path)
    with baseline_file.open("r", encoding="utf-8") as handle:
        baseline = json.load(handle)

    baseline_files = {entry["path"]: entry for entry in baseline.get("files", [])}
    current_files = {entry["path"]: entry for entry in current_results}

    files: list[dict] = []
    all_paths = sorted(set(baseline_files) | set(current_files))

    for path in all_paths:
        baseline_entry = baseline_files.get(path)
        current_entry = current_files.get(path)

        if baseline_entry and not current_entry:
            files.append({"path": path, "status": "REMOVED", "baseline": baseline_entry, "current": None, "diffs": []})
            continue

        if current_entry and not baseline_entry:
            files.append({"path": path, "status": "NEW", "baseline": None, "current": current_entry, "diffs": []})
            continue

        baseline_hashes = baseline_entry["hashes"]
        current_hashes = current_entry["hashes"]
        if algorithms is None:
            shared_algorithms = sorted(set(baseline_hashes) & set(current_hashes))
        else:
            shared_algorithms = [algo for algo in algorithms if algo in baseline_hashes and algo in current_hashes]

        diffs: list[dict] = []
        changed = False
        for algo in shared_algorithms:
            b = baseline_hashes.get(algo)
            c = current_hashes.get(algo)
            if b != c:
                changed = True
                diffs.append({"algorithm": algo, "baseline": b, "current": c})

        status = "UNCHANGED" if not changed else "MODIFIED"
        files.append({"path": path, "status": status, "baseline": baseline_entry, "current": current_entry, "diffs": diffs})

    report_metadata = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "baseline": str(baseline_file.resolve()),
        "total_files": len(files),
    }
    if algorithms is not None:
        report_metadata["algorithms"] = algorithms
    if examiner:
        report_metadata["examiner"] = examiner

    report = {
        "verification": True,
        "report_metadata": report_metadata,
        "files": files,
    }

    return report


def render_text_verification(report: dict) -> str:
    meta = report["report_metadata"]
    lines = [
        "=" * 72,
        "FORENSIC HASH VERIFICATION REPORT",
        "=" * 72,
        f"Baseline : {meta.get('baseline')}",
    ]
    if meta.get("examiner"):
        lines.append(f"Examiner : {meta['examiner']}")
    if meta.get("algorithms"):
        lines.append(f"Algorithms: {', '.join(meta['algorithms']).upper()}")
    lines.extend(
        [
            f"Generated: {meta.get('generated')}",
            "=" * 72,
            "",
        ]
    )

    for entry in report["files"]:
        status = entry["status"]
        lines.append(f"[{status[0]}] {status}: {entry['path']}")
        if entry.get("diffs"):
            for d in entry["diffs"]:
                lines.append(f"    {d['algorithm'].upper():8}: {d['baseline']} -> {d['current']}")

    return "\n".join(lines)


def render_csv_verification(report: dict) -> str:
    fieldnames = ["path", "status", "algorithm", "baseline_hash", "current_hash"]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    for entry in report["files"]:
        if entry["status"] in ("NEW", "REMOVED"):
            writer.writerow({"path": entry["path"], "status": entry["status"], "algorithm": "", "baseline_hash": "", "current_hash": ""})
            continue

        if not entry.get("diffs"):
            writer.writerow({"path": entry["path"], "status": entry["status"], "algorithm": "", "baseline_hash": "", "current_hash": ""})
            continue

        for d in entry["diffs"]:
            writer.writerow({"path": entry["path"], "status": entry["status"], "algorithm": d["algorithm"], "baseline_hash": d["baseline"], "current_hash": d["current"]})

    return buffer.getvalue()


def apply_verification_to_baseline(current_results: list[dict], baseline_path: str | Path, target: str | Path, algorithms: list[str], examiner: str, make_backup: bool = True) -> None:
    """Update the baseline JSON to match current results.

    Creates a timestamped backup of the existing baseline (if present) then
    writes a new baseline file containing the current scan report structure.
    """
    baseline_file = Path(baseline_path)

    try:
        if baseline_file.exists() and make_backup:
            stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
            backup_path = baseline_file.with_name(f"{baseline_file.stem}.{stamp}.bak{baseline_file.suffix}")
            baseline_file.replace(backup_path)

        new_baseline = build_report(current_results, target, algorithms, examiner)
        baseline_file.write_text(json.dumps(new_baseline, indent=2), encoding="utf-8")
    except OSError as exc:
        raise


def _validate_algorithms(algorithms: list[str]) -> list[str]:
    invalid = [algo for algo in algorithms if algo not in SUPPORTED_ALGORITHMS]
    if invalid:
        supported = ", ".join(SUPPORTED_ALGORITHMS)
        raise ValueError(f"Unsupported algorithm(s): {', '.join(invalid)}. Supported: {supported}")
    return algorithms


def _resolve_output_format(output_path: str | Path, report_format: str) -> str:
    suffix_map = {
        ".txt": "text",
        ".json": "json",
        ".csv": "csv",
        ".pdf": "pdf",
    }
    suffix = Path(output_path).suffix.lower()
    if suffix not in suffix_map:
        supported = ", ".join(suffix_map)
        raise ValueError(
            f"Unsupported output extension '{suffix}'. "
            f"Use one of {supported}."
        )
    return suffix_map[suffix]


def _write_output(report: dict, output_path: str | Path, report_format: str = "auto") -> None:
    path = Path(output_path)
    if not path.parent or str(path.parent) == ".":
        path = Path.cwd() / "output" / path.name
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = _resolve_output_format(path, report_format)
    # If this is a verification report, use the verification renderers
    if report.get("verification"):
        if fmt == "json":
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        elif fmt == "text":
            path.write_text(render_text_verification(report), encoding="utf-8")
        elif fmt == "csv":
            path.write_text(render_csv_verification(report), encoding="utf-8", newline="")
        elif fmt == "pdf":
            write_pdf_verification_report(report, path)
        else:
            raise ValueError(f"Unsupported verification report format: {fmt}")
        return

    # Standard scan report rendering
    if fmt == "json":
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    elif fmt == "text":
        path.write_text(render_text_report(report), encoding="utf-8")
    elif fmt == "csv":
        path.write_text(render_csv_report(report), encoding="utf-8", newline="")
    elif fmt == "pdf":
        write_pdf_report(report, path)
    else:
        raise ValueError(f"Unsupported report format: {fmt}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Forensic Hash Tool — verify digital evidence integrity via cryptographic hashes."
    )
    parser.add_argument("target", help="File or directory path to scan")
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories when target is a folder",
    )
    parser.add_argument(
        "-a",
        "--algorithms",
        nargs="+",
        default=["md5", "sha256"],
        help="Hash algorithms to compute (default: md5 sha256). Use commas for multiple values, e.g. md5,sha1",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write report to .txt, .json, .csv, or .pdf file",
    )
    parser.add_argument(
        "-e",
        "--examiner",
        help="Examiner name to record in the report",
    )
    parser.add_argument(
        "-v",
        "--verify",
        metavar="BASELINE",
        help="Compare results against a previous JSON baseline report",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError, ValueError):
            pass

    args = parse_args(argv)
    algorithms_raw: list[str] = []
    for value in args.algorithms:
        algorithms_raw.extend([item.strip() for item in value.split(",") if item.strip()])
    algorithms = _validate_algorithms(algorithms_raw)

    try:
        results = scan_target(args.target, args.recursive, algorithms)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    report = build_report(results, args.target, algorithms, args.examiner)

    if args.verify:
        try:
            verification_struct = build_verification_struct(results, args.verify, algorithms, args.examiner)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"Verification failed: {exc}", file=sys.stderr)
            return 1

        # If an output file was requested, write the verification report
        if args.output:
            try:
                _write_output(verification_struct, args.output)
                print(f"Verification report saved: {Path(args.output).resolve()}", file=sys.stderr)
            except ValueError as exc:
                print(exc, file=sys.stderr)
                return 1

            # Update baseline after successful report generation
            try:
                apply_verification_to_baseline(results, args.verify, args.target, algorithms, args.examiner)
                print(f"Baseline updated: {Path(args.verify).resolve()}", file=sys.stderr)
            except Exception as exc:
                print(f"Baseline update failed: {exc}", file=sys.stderr)
            return 0

        # No output file — print textual verification summary
        print(render_text_verification(verification_struct))

        try:
            apply_verification_to_baseline(results, args.verify, args.target, algorithms, args.examiner)
            print(f"Baseline updated: {Path(args.verify).resolve()}", file=sys.stderr)
        except Exception as exc:
            print(f"Baseline update failed: {exc}", file=sys.stderr)

        return 0

    # No verification requested — write/print the scan report
    if args.output:
        try:
            _write_output(report, args.output)
            print(f"Report saved: {Path(args.output).resolve()}", file=sys.stderr)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
    else:
        print(render_text_report(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
