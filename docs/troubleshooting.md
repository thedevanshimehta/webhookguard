# WebhookGuard Troubleshooting

This guide covers common setup and local-development problems when running
WebhookGuard on Windows with Git Bash or PowerShell.

## Confirm the project directory

Commands must be run from the repository root, the directory containing
`README.md`, `app/`, `receiver/`, and `requirements.txt`.

In Git Bash:

```bash
cd ~/Desktop/webhookguard-final
pwd
```

In PowerShell:

```powershell
Set-Location C:\Users\Vedansh\Desktop\webhookguard-final
Get-Location
```

The terminal prompt is not proof of the current directory. If `PS1` was
customized in Git Bash, it may display a path that is different from the real
working directory.

## Create and activate the virtual environment

Create the project environment once:

```bash
python -m venv .venv
```

Activate it in Git Bash:

```bash
source .venv/Scripts/activate
```

Activate it in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

After activation, verify which Python is being used:

```bash
python -c "import sys; print(sys.executable)"
```

The path should end in `.venv/Scripts/python` or `.venv\Scripts\python.exe`.
If `.venv/Scripts/activate` does not exist, either the command was run outside
the repository root or the virtual environment has not been created there.

Deactivate the environment when finished:

```bash
deactivate
```

If PowerShell reports that script execution is disabled, allow scripts only
for the current PowerShell process and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Install dependencies

With the virtual environment active, install the pinned project dependencies:

```bash
python -m pip install -r requirements.txt
```

Using `python -m pip` helps ensure that pip belongs to the active virtual
environment.

## Configure the environment file

The receiver, sender CLI, and attack scripts read configuration from `.env`.
Create it from the example file:

In Git Bash:

```bash
cp .env.example .env
```

In PowerShell:

```powershell
Copy-Item .env.example .env
```

Generate a real signing key:

```bash
python -m keys.key_manager
```

Copy the generated `k1:<secret>` value into `.env`:

```env
WEBHOOKGUARD_KEYS=k1:<generated-secret>
```

The placeholder in `.env.example` is intentionally rejected. Never commit
`.env`, secrets, databases, or generated log files.

## `WEBHOOKGUARD_KEYS is not set`

This error means that `.env` is missing, is in a different directory, or does
not contain `WEBHOOKGUARD_KEYS`. Confirm that `.env` exists in the repository
root and contains a generated key:

```bash
test -f .env && echo ".env exists"
grep '^WEBHOOKGUARD_KEYS=' .env
```

Do not paste the secret into an issue or commit. If the variable is present but
the application still cannot load it, confirm that the command is being run
from the repository root and that the file is named exactly `.env`, not
`.env.txt`.

## Start the protected receiver

With `.env` configured and the virtual environment active:

```bash
python -m app.main
```

The default receiver listens on `http://127.0.0.1:5000`. The dashboard is
available at `http://127.0.0.1:5000/dashboard`, and the payment ledger is
available at `http://127.0.0.1:5000/ledger`.

If port 5000 is already in use, stop the process using it or choose another
port in `.env`:

```env
PORT=5050
```

When changing the port, use the same port in the sender's `--url` argument.

## `Connection refused` from the sender

Start the receiver first and keep its terminal running:

```bash
python -m app.main
```

Then, from a second terminal in the repository root with the virtual
environment active, run the sender. If the receiver uses a non-default port,
pass the matching URL with `--url`.

## Run the tests

Run the test suite from the repository root:

```bash
pytest tests/ -v
```

Tests use their own configuration and should not require a real `.env` secret.
