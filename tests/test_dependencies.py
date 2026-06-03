from app.dependencies import discover_python_dependency_components, parse_dependency_string, parse_pyproject_file, parse_requirements_file


def test_parse_requirements_file_extracts_pins_ranges_extras_and_direct_refs(workspace_temp_dir) -> None:
    requirements = workspace_temp_dir / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "# comment",
                "flask==3.0.0",
                "requests == 2.31.0",
                "django>=5.0,<6.0",
                "uvicorn[standard]~=0.30.0 ; python_version >= '3.12'",
                "internal-lib @ https://example.com/internal-lib.zip",
                "-r dev-requirements.txt",
            ]
        ),
        encoding="utf-8",
    )

    components = parse_requirements_file(requirements)

    assert [(component.name, component.version, component.version_specifier) for component in components] == [
        ("flask", "3.0.0", "==3.0.0"),
        ("requests", "2.31.0", "==2.31.0"),
        ("django", None, ">=5.0,<6.0"),
        ("uvicorn", None, "~=0.30.0"),
        ("internal-lib", None, "@ https://example.com/internal-lib.zip"),
    ]
    assert all(component.ecosystem == "PyPI" for component in components)


def test_parse_pyproject_file_extracts_project_and_optional_pins(workspace_temp_dir) -> None:
    pyproject = workspace_temp_dir / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "typer==0.12.3",
  "rich>=13.0",
]

[project.optional-dependencies]
test = [
  "pytest==8.4.0",
]
""".strip(),
        encoding="utf-8",
    )

    components = parse_pyproject_file(pyproject)

    assert [(component.name, component.version) for component in components] == [
        ("typer", "0.12.3"),
        ("rich", None),
        ("pytest", "8.4.0"),
    ]


def test_discover_python_dependency_components_reports_notes(workspace_temp_dir) -> None:
    (workspace_temp_dir / "requirements.txt").write_text("flask==3.0.0\ndjango>=5.0\n", encoding="utf-8")

    components, notes = discover_python_dependency_components(workspace_temp_dir)

    assert [component.name for component in components] == ["flask", "django"]
    assert any("Parsed 2 Python dependency" in note for note in notes)
    assert any("1 exact version candidate" in note for note in notes)


def test_parse_dependency_string_strips_markers_and_inline_comments() -> None:
    dependency = parse_dependency_string("starlette==0.37.2 ; python_version >= '3.12' # runtime")

    assert dependency is not None
    assert dependency.name == "starlette"
    assert dependency.version == "0.37.2"
    assert dependency.version_specifier == "==0.37.2"
