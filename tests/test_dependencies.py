from app.dependencies import discover_python_dependency_components, parse_pyproject_file, parse_requirements_file


def test_parse_requirements_file_extracts_simple_pins(workspace_temp_dir) -> None:
    requirements = workspace_temp_dir / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "# comment",
                "flask==3.0.0",
                "requests == 2.31.0",
                "django>=5.0",
                "-r dev-requirements.txt",
            ]
        ),
        encoding="utf-8",
    )

    components = parse_requirements_file(requirements)

    assert [(component.name, component.version) for component in components] == [
        ("flask", "3.0.0"),
        ("requests", "2.31.0"),
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
        ("pytest", "8.4.0"),
    ]


def test_discover_python_dependency_components_reports_notes(workspace_temp_dir) -> None:
    (workspace_temp_dir / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")

    components, notes = discover_python_dependency_components(workspace_temp_dir)

    assert [component.name for component in components] == ["flask"]
    assert any("Parsed 1 pinned Python dependency" in note for note in notes)
