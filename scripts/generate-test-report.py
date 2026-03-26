#!/usr/bin/env python3
"""
Generate a test-report.pdf from CI artifacts.

Reads:
  - test-reports/firmware-unit/*.xml   (JUnit XML from GoogleTest)
  - test-reports/python-keepkey/*.xml  (JUnit XML from python-keepkey)
  - test-reports/screenshots/*.png     (OLED captures)

Produces:
  - test-report.pdf
"""

import glob
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# fpdf2 is installed in CI via pip
try:
    from fpdf import FPDF
except ImportError:
    print("ERROR: fpdf2 not installed. Run: pip install fpdf2", file=sys.stderr)
    sys.exit(1)


def parse_junit_xml(xml_path):
    """Parse a JUnit XML file and return test results."""
    results = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Handle both <testsuites> and <testsuite> root elements
        suites = root.findall(".//testsuite")
        if not suites and root.tag == "testsuite":
            suites = [root]

        for suite in suites:
            suite_name = suite.get("name", "unknown")
            for tc in suite.findall("testcase"):
                name = tc.get("name", "unknown")
                classname = tc.get("classname", suite_name)
                time_s = float(tc.get("time", "0"))

                failure = tc.find("failure")
                error = tc.find("error")
                skipped = tc.find("skipped")

                if failure is not None:
                    status = "FAIL"
                    message = failure.get("message", "")
                elif error is not None:
                    status = "ERROR"
                    message = error.get("message", "")
                elif skipped is not None:
                    status = "SKIP"
                    message = skipped.get("message", "")
                else:
                    status = "PASS"
                    message = ""

                results.append({
                    "suite": classname,
                    "name": name,
                    "status": status,
                    "time": time_s,
                    "message": message[:120],  # truncate long messages
                })
    except ET.ParseError as e:
        results.append({
            "suite": os.path.basename(xml_path),
            "name": "XML_PARSE_ERROR",
            "status": "ERROR",
            "time": 0,
            "message": str(e)[:120],
        })
    return results


def collect_results(base_dir):
    """Collect all JUnit XML results from test-reports/."""
    unit_results = []
    python_results = []

    for xml_file in sorted(glob.glob(os.path.join(base_dir, "firmware-unit", "*.xml"))):
        unit_results.extend(parse_junit_xml(xml_file))

    for xml_file in sorted(glob.glob(os.path.join(base_dir, "python-keepkey", "*.xml"))):
        python_results.extend(parse_junit_xml(xml_file))

    return unit_results, python_results


def collect_screenshots(base_dir):
    """Collect OLED screenshot paths."""
    patterns = [
        os.path.join(base_dir, "screenshots", "*.png"),
        os.path.join(base_dir, "screenshots", "**", "*.png"),
    ]
    shots = []
    for pat in patterns:
        shots.extend(sorted(glob.glob(pat, recursive=True)))
    return shots


def count_status(results):
    """Count pass/fail/skip/error."""
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return counts


class TestReportPDF(FPDF):
    def __init__(self, branch, commit, fw_version):
        super().__init__()
        self.branch = branch
        self.commit = commit
        self.fw_version = fw_version
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 8, "KeepKey Firmware Test Report", new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Helvetica", "", 8)
        self.cell(0, 5,
                  f"Branch: {self.branch}  |  Commit: {self.commit}  |  "
                  f"Version: {self.fw_version}  |  {self.timestamp}",
                  new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def add_summary(self, unit_counts, python_counts):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, "Summary", new_x="LMARGIN", new_y="NEXT")

        total_pass = unit_counts["PASS"] + python_counts["PASS"]
        total_fail = unit_counts["FAIL"] + python_counts["FAIL"]
        total_error = unit_counts["ERROR"] + python_counts["ERROR"]
        total_skip = unit_counts["SKIP"] + python_counts["SKIP"]
        total = total_pass + total_fail + total_error + total_skip

        # Overall verdict
        if total_fail > 0 or total_error > 0:
            verdict = "FAIL"
            color = (220, 50, 50)
        elif total == 0:
            verdict = "NO TESTS"
            color = (200, 150, 0)
        else:
            verdict = "PASS"
            color = (50, 150, 50)

        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*color)
        self.cell(0, 10, f"Overall: {verdict}", new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_text_color(0, 0, 0)

        # Counts table
        self.set_font("Helvetica", "", 10)
        self.ln(3)

        col_w = [60, 30, 30, 30, 30]
        headers = ["Category", "Pass", "Fail", "Error", "Skip"]
        for i, h in enumerate(headers):
            self.set_font("Helvetica", "B", 9)
            self.cell(col_w[i], 7, h, border=1)
        self.ln()

        self.set_font("Helvetica", "", 9)
        for label, counts in [("Unit Tests", unit_counts), ("Python Integration", python_counts)]:
            self.cell(col_w[0], 7, label, border=1)
            self.cell(col_w[1], 7, str(counts["PASS"]), border=1, align="C")

            self.set_text_color(220, 50, 50) if counts["FAIL"] > 0 else self.set_text_color(0, 0, 0)
            self.cell(col_w[2], 7, str(counts["FAIL"]), border=1, align="C")
            self.set_text_color(0, 0, 0)

            self.set_text_color(220, 50, 50) if counts["ERROR"] > 0 else self.set_text_color(0, 0, 0)
            self.cell(col_w[3], 7, str(counts["ERROR"]), border=1, align="C")
            self.set_text_color(0, 0, 0)

            self.cell(col_w[4], 7, str(counts["SKIP"]), border=1, align="C")
            self.ln()

        # Totals
        self.set_font("Helvetica", "B", 9)
        self.cell(col_w[0], 7, "TOTAL", border=1)
        self.cell(col_w[1], 7, str(total_pass), border=1, align="C")
        self.set_text_color(220, 50, 50) if total_fail > 0 else self.set_text_color(0, 0, 0)
        self.cell(col_w[2], 7, str(total_fail), border=1, align="C")
        self.set_text_color(0, 0, 0)
        self.set_text_color(220, 50, 50) if total_error > 0 else self.set_text_color(0, 0, 0)
        self.cell(col_w[3], 7, str(total_error), border=1, align="C")
        self.set_text_color(0, 0, 0)
        self.cell(col_w[4], 7, str(total_skip), border=1, align="C")
        self.ln(10)

    def add_test_section(self, title, results):
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")

        if not results:
            self.set_font("Helvetica", "I", 9)
            self.cell(0, 6, "No test results found.", new_x="LMARGIN", new_y="NEXT")
            self.ln(3)
            return

        col_w = [75, 15, 15, 85]
        self.set_font("Helvetica", "B", 8)
        for i, h in enumerate(["Test Name", "Status", "Time", "Details"]):
            self.cell(col_w[i], 6, h, border=1)
        self.ln()

        self.set_font("Helvetica", "", 7)
        for r in results:
            # Truncate test name to fit
            name = r["name"][:45]

            # Status color
            if r["status"] == "PASS":
                self.set_text_color(0, 100, 0)
            elif r["status"] in ("FAIL", "ERROR"):
                self.set_text_color(220, 50, 50)
            else:
                self.set_text_color(150, 150, 0)

            self.cell(col_w[0], 5, name, border=1)
            self.cell(col_w[1], 5, r["status"], border=1, align="C")
            self.set_text_color(0, 0, 0)
            self.cell(col_w[2], 5, f"{r['time']:.2f}s", border=1, align="R")
            self.cell(col_w[3], 5, r["message"][:50], border=1)
            self.ln()

            # Page break check
            if self.get_y() > 270:
                self.add_page()

        self.ln(5)

    def add_screenshots(self, screenshot_paths):
        if not screenshot_paths:
            return

        self.add_page()
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, "OLED Screenshots", new_x="LMARGIN", new_y="NEXT")

        for i, path in enumerate(screenshot_paths):
            if self.get_y() > 230:
                self.add_page()

            label = os.path.basename(path).replace(".png", "").replace("_", " ")
            self.set_font("Helvetica", "", 8)
            self.cell(0, 5, label, new_x="LMARGIN", new_y="NEXT")

            try:
                # OLED screenshots are typically 128x64, scale up 2x
                self.image(path, w=60, h=30)
            except Exception as e:
                self.cell(0, 5, f"[Could not load: {e}]", new_x="LMARGIN", new_y="NEXT")

            self.ln(3)


def main():
    # Read environment or args
    branch = os.environ.get("BRANCH", os.popen("git rev-parse --abbrev-ref HEAD").read().strip())
    commit = os.environ.get("COMMIT_SHA", os.popen("git rev-parse --short HEAD").read().strip())
    fw_version = os.environ.get("FW_VERSION", "unknown")
    base_dir = os.environ.get("TEST_REPORTS_DIR", "test-reports")
    output = os.environ.get("OUTPUT_PDF", "test-report.pdf")

    print(f"Generating test report for {branch} ({commit}), firmware {fw_version}")
    print(f"Reading from: {base_dir}")

    unit_results, python_results = collect_results(base_dir)
    screenshots = collect_screenshots(base_dir)

    print(f"  Unit tests: {len(unit_results)}")
    print(f"  Python tests: {len(python_results)}")
    print(f"  Screenshots: {len(screenshots)}")

    unit_counts = count_status(unit_results)
    python_counts = count_status(python_results)

    pdf = TestReportPDF(branch, commit, fw_version)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.add_summary(unit_counts, python_counts)
    pdf.add_test_section("Unit Tests (GoogleTest)", unit_results)
    pdf.add_test_section("Python Integration Tests", python_results)
    pdf.add_screenshots(screenshots)
    pdf.output(output)

    print(f"Report written to: {output}")

    # Exit non-zero if any failures
    total_fail = unit_counts["FAIL"] + python_counts["FAIL"]
    total_error = unit_counts["ERROR"] + python_counts["ERROR"]
    if total_fail > 0 or total_error > 0:
        print(f"WARNING: {total_fail} failures, {total_error} errors")
        # Don't exit non-zero — let the report be uploaded even with failures
    return 0


if __name__ == "__main__":
    sys.exit(main())
