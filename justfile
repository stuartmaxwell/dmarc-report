# Set the default recipe to list all available commands
@default:
    @just --list

#Set the uv command to run a tool
uv-tool := "uv tool run"

# Run Ruff linting
@lint:
    {{uv-tool}} ruff check

# Run tests wth pytest
@test:
    uv run pytest

# Run nox
@nox:
    {{uv-tool}} nox --session test

# Run Ruff formatting
@format:
    {{uv-tool}} ruff format

# Sync the package
@sync:
    uv sync --all-extras

# Sync the package
@sync-up:
    uv sync --all-extras --upgrade

# Lock the package version
@lock:
    uv lock

# Build the package
@build:
    uv build

# Publish the package - this requires a $HOME/.pypirc file with your credentials
@publish:
      rm -rf ./dist/*
      uv build
      {{uv-tool}} twine check dist/*
      {{uv-tool}} twine upload dist/*

# Install pre-commit hooks
@pc-install:
    {{uv-tool}} pre-commit install

# Upgrade pre-commit hooks
@pc-up:
    {{uv-tool}} pre-commit autoupdate

# Run pre-commit hooks
@pc-run:
    {{uv-tool}} pre-commit run --all-files

# Use BumpVer to increase the patch version number. Use just bump -d to view a dry-run.
@bump *ARGS:
    uv run bumpver update --patch {{ ARGS }}
    uv sync
    git add uv.lock
    git commit -m "Bump version"
    git push

# Use BumpVer to increase the minor version number. Use just bump -d to view a dry-run.
@bump-minor *ARGS:
    uv run bumpver update --minor {{ ARGS }}
    uv sync
    git add uv.lock
    git commit -m "Bump version"
    git push

# Use BumpVer to increase the major version number. Use just bump -d to view a dry-run.
@bump-major *ARGS:
    uv run bumpver update --major {{ ARGS }}
    uv sync
    git add uv.lock
    git commit -m "Bump version"
    git push

# Create a new GitHub release - this requires Python 3.11 or newer, and the GitHub CLI must be installed and configured
version := `echo "from tomllib import load; print(load(open('pyproject.toml', 'rb'))['project']['version'])" | uv run - `

[confirm("Are you sure you want to create a new release?\nThis will create a new GitHub release and will build and deploy a new version to PyPi.\nYou should have already updated the version number using one of the bump recipes.\nTo check the version number, run just version.\n\nCreate release?")]
@release:
    echo "Creating a new release for v{{version}}"
    git pull
    gh release create "v{{version}}" --generate-notes

@version:
    git pull
    echo {{version}}
