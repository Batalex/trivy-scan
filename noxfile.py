import json
from pathlib import Path

import nox

nox.options.default_venv_backend = "uv"
nox.options.reuse_venv = "yes"
nox.options.sessions = []


@nox.session
def scan(session: nox.Session) -> None:
    """Run Trivy scan on folder.

    Create a xlsx report with medium/high/critical CVEs.
    """
    match session.posargs:
        case [path_candidate, *_]:
            if not (path := Path(path_candidate).resolve()).exists():
                session.log("Cannot find path.")
                return
        case _:
            session.log("You must pass a single path to a build folder to continue.")
            return

    session.run_install(
        "uv",
        "sync",
        "--frozen",
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )
    session.log("Starting scan")
    session.run(
        "trivy",
        "rootfs",
        f"{path.absolute()}",
        "-f",
        "json",
        "--output",
        f"report_{path.name}.json",
        external=True,
    )
    session.log("Parsing Trivy report")
    session.run(
        "uv",
        "run",
        "convert.py",
        f"report_{path.name}.json",
        env={
            "UV_PROJECT_ENVIRONMENT": session.virtualenv.location,
        },
    )


@nox.session
def diff(session: nox.Session) -> None:
    """Compare two json reports to display resolved CVEs.

    Usage:
        nox -s diff -- run_before.json run_after.json
    """
    match session.posargs:
        case [path_candidate1, path_candidate2, *_]:
            if not (path1 := Path(path_candidate1).resolve()).exists():
                session.log(f"Cannot find {path1}.")
                return
            if not (path2 := Path(path_candidate2).resolve()).exists():
                session.log(f"Cannot find {path2}.")
                return
        case _:
            session.log("You must pass two paths to continue.")
            return

    with path1.open("r", encoding="utf8") as f:
        report1 = json.load(f)

    with path2.open("r", encoding="utf8") as f:
        report2 = json.load(f)

    cves_before = {
        vuln["VulnerabilityID"] for vuln in report1["Results"][0]["Vulnerabilities"]
    }
    cves_after = {
        vuln["VulnerabilityID"] for vuln in report2["Results"][0]["Vulnerabilities"]
    }

    diff = cves_before - cves_after
    print(f"{len(diff)} CVE(s) addressed:")
    print(" ".join(sorted(diff)))
