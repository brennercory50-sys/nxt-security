# Reporting

Generate a shareable report from all findings, or from one assessment.

```sh
nxtsec report                                  # all findings, Markdown to stdout
nxtsec report --assessment asm_123             # one assessment
nxtsec report --format html -o report.html     # self-contained HTML
nxtsec report --format json -o findings.json
nxtsec report --format csv  -o findings.csv
nxtsec report --min-severity HIGH --open       # filter
```

Formats: **markdown**, **html**, **json**, **csv**.

Every report has an executive summary, severity distribution, methodology,
scope (with the assessments included), the findings (severity-ordered, with
impact, remediation, references and evidence ids), and an appendix. The HTML
report is a single self-contained file (inline CSS, no external requests,
light/dark aware) suitable for handing to a stakeholder. All rendered text is
redacted, and output is deterministic for the same data.
