import nox
from pathlib import Path

nox.options.default_venv_backend = "uv"
nox.options.reuse_venv = "yes"
nox.options.sessions = []


@nox.session
def scan(session: nox.Session) -> None:
    """Run Trivy scan on folder."""
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
        "report.json",
        external=True,
    )
    session.log("Parsing Trivy report")
    session.run(
        "uv",
        "run",
        "convert.py",
        "report.json",
        env={
            "UV_PROJECT_ENVIRONMENT": session.virtualenv.location,
        },
    )
