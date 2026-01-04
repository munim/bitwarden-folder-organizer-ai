# Bitwarden Folder Organizer using AI

Organize your Bitwarden vault into meaningful folders/collections using an LLM — **powered by the Bitwarden CLI (`bw`)**.

This project reads your vault directly via `bw`, sends only **non-sensitive metadata** to an LLM in batches, and then moves items:

- **Personal vault items** → moved by updating `folderId` (folders)
- **Organization items** → moved by replacing collection assignments (collections)

## Why this exists
Bitwarden is great at storing credentials, but it’s easy for vaults to become messy over time. This tool automates vault organization while keeping an explicit, strict privacy boundary: the LLM never receives secrets.

## Features
- **End-to-end `bw` workflow**
  - List items/folders from the vault via `bw`
  - Create missing folders/collections via `bw`
  - Move items via `bw edit ...`
- **Batch LLM categorization** (OpenRouter or Requesty)
- **Domain cache** to reduce repeated LLM calls
- **Domain-to-folder mapping** (YAML) to auto-categorize without LLM cost
- **Homelab detection**
  - If an item URL points to a private IP (or resolves to one), it is categorized as `Homelab`
- **Optional “Dead” detection** (`--check-reachability`)
  - If an item has URLs and none are reachable, it is categorized as `Dead`
- **Safe-by-default execution**
  - Dry-run is the default; `--apply` is required to change your vault

## Security & Privacy Model (read this)
This tool enforces a hard boundary around what is sent to the LLM.

### Never sent to LLM
- Passwords
- Notes
- TOTP
- Custom field values (only field names may be sent)
- Card/identity contents

### Allowed LLM fields
For each vault item, your LLM prompt may include only:
- `id`
- `name`
- `type`
- Current folder name (name only)
- Login URIs (`login.uris[].uri`) (URLs only)
- Username (masked if it looks like an email: `***@domain.com`)
- Custom field names (names only)

The code includes a runtime guard that refuses to send prompts containing forbidden keys like `"password"`, `"notes"`, `"totp"`, or custom field `"value"`.

## How categorization maps to folders/collections
The LLM returns categories that may look like `Tools/Development`.

This project uses the following rules:
- `Personal/Homelab` → `Homelab`
- `Dead` → `Dead`
- Everything else → **top-level** segment only
  - `Tools/Development` → `Tools`
  - `Financial/Banking` → `Financial`

### Personal vs Organization items
- Personal items are moved by setting `folderId`.
- Organization items are moved by **replacing** the item’s existing collection assignments with a single collection matching the category label, **inside the same organization** the item already belongs to.

## Prerequisites
- Python **3.11+**
- [`uv`](https://github.com/astral-sh/uv) (recommended)
- Bitwarden CLI (`bw`)
- An API key for your chosen LLM provider:
  - `OPENROUTER_API_KEY` for OpenRouter
  - `REQUESTY_API_KEY` for Requesty

## Installation

```bash
git clone https://github.com/munim/bitwarden-folder-organizer-ai.git
cd bitwarden-folder-organizer-ai

# Install dependencies
uv sync
```

## Bitwarden CLI setup

### 1) Install `bw`
Follow Bitwarden’s official CLI installation docs: https://bitwarden.com/help/cli/

### 2) Login and unlock
This tool requires an unlocked vault session.

```bash
bw login
export BW_SESSION="$(bw unlock --raw)"
```

Confirm status:

```bash
bw status
```

It should show `"status": "unlocked"`.

### Session security
A `BW_SESSION` token grants full access to your vault while valid. Treat it like a password.

## Configuration

### LLM provider API keys
Create a `.env` file (or export environment variables) like:

```env
OPENROUTER_API_KEY=your_key_here
# or
REQUESTY_API_KEY=your_key_here
```

Never commit `.env` to version control.

### Optional domain-to-folder mapping
You can auto-categorize certain items without sending them to the LLM.

Create a YAML file such as `domain_folder_map.yaml`:

```yaml
- domain: google.com
  folder: "Google"
- domain: example.org
  folder: "Work"
```

Rules:
- If an item is already in a folder matching one of the mapped folders → it is categorized immediately
- If a username contains a mapped domain → it is categorized immediately

## Usage

### Quick start (dry-run)
Dry-run is the default. It prints planned moves without modifying your vault.

```bash
uv run python main.py --dry-run
```

### Apply changes
Actually moves items, creating missing folders/collections as needed:

```bash
uv run python main.py --apply
```

## Examples

### 1) Safest first run (single batch)
Limits work while you verify categorization quality:

```bash
uv run python main.py --dry-run --max-batches 1
```

### 2) Use a specific model

```bash
uv run python main.py --dry-run --model claude-3-haiku-20240307
```

### 3) Switch LLM provider

```bash
uv run python main.py --dry-run --provider requesty
```

### 4) Tune batching and pacing
Helpful if you hit throttling or want to reduce load:

```bash
uv run python main.py --apply --batch-size 10 --sleep-between-batches 5 --item-delay 0.2
```

### 5) Enable reachability checks (“Dead”)
This feature is **off by default**.

```bash
uv run python main.py --dry-run --check-reachability
```

### 6) Use a domain-to-folder map (auto-categorize without LLM)

```bash
uv run python main.py --dry-run --domain-folder-map domain_folder_map.yaml
```

### 7) Process only items matching a search query

```bash
uv run python main.py --dry-run --search github
```

### 8) Process only items in a specific folder

```bash
uv run python main.py --dry-run --folderid <folder-id>
```

Tip (find folder ids):

```bash
bw list folders
```

### 9) Process only items in a specific organization

```bash
uv run python main.py --dry-run --organizationid <org-id>
```

Tip (find organization ids):

```bash
bw list organizations
```

### 10) Process only items in a specific collection

```bash
uv run python main.py --dry-run --collectionid <collection-id>
```

Tip (find collection ids for an org):

```bash
bw list org-collections --organizationid <org-id>
```

### 11) Include trashed items

```bash
uv run python main.py --dry-run --trash
```

### 12) Sync before reading
Useful if you make changes in the Bitwarden UI and want the latest state:

```bash
uv run python main.py --dry-run --sync
```

### 13) Pass session explicitly (instead of `BW_SESSION`)

```bash
uv run python main.py --dry-run --session "<your-bw-session>"
```

## CLI Reference

Run this for the authoritative list:

```bash
uv run python main.py --help
```

### LLM options
- `--provider {openrouter,requesty}`: LLM provider backend (default: `openrouter`).
- `--model <model>`: LLM model name (default: `claude-3-haiku-20240307`).
- `--batch-size, -b <N>`: Items per LLM request batch (default: `10`).
- `--max-batches <N>`: Limit to the first N batches (useful for testing).
- `--domain-folder-map <path>`: YAML mapping for auto-categorization.

### Classification toggles
- `--check-reachability`: If set, categorize logins with unreachable URLs as `Dead`.

### Bitwarden access
- `--session <token>`: Bitwarden session token (otherwise uses `BW_SESSION`).
- `--sync`: Run `bw sync` before listing items.

### Item filters
These flags are passed through to `bw list items` to reduce the scope.

- `--search <text>`: Bitwarden search query.
- `--folderid <id>`: Filter by folder id (`null` is accepted by `bw`).
- `--collectionid <id>`: Filter by collection id.
- `--organizationid <id>`: Filter by organization id.
- `--trash`: Include items in the trash.

### Execution
- `--dry-run`: Print planned changes without modifying the vault (default unless `--apply`).
- `--apply`: Apply changes to the vault.
- `--sleep-between-batches <seconds>`: Delay between LLM requests (default: `5`).
- `--item-delay <seconds>`: Delay between each `bw edit` mutation (default: `0.2`).

## Troubleshooting

### Vault locked / session missing
If you see an error about the vault not being unlocked:

```bash
bw login
export BW_SESSION="$(bw unlock --raw)"
```

Then rerun.

### Missing API key
- OpenRouter requires `OPENROUTER_API_KEY`
- Requesty requires `REQUESTY_API_KEY`

### Too slow / rate limiting
- Reduce `--batch-size`
- Increase `--sleep-between-batches`
- Increase `--item-delay`

### Folder/collection creation errors
If Bitwarden refuses creation, check:
- you are unlocked
- you have permissions in the organization (for org collections)

## Development

### Project layout
- `main.py`: CLI entrypoint and orchestration
- `classify_bitwarden_vault_items.py`: categorization library + `bw` integration + LLM safety guardrails

### Quick checks

```bash
python -m py_compile main.py classify_bitwarden_vault_items.py
```

## Contributing
PRs are welcome.

- Keep security boundaries intact: never add secrets to LLM payloads.
- Prefer small, reviewable changes.

## License
MIT (see `LICENSE`).
