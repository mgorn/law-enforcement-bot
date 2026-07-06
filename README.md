# Law Enforcement Bot

A Discord "moderation" bot built with `discord.py` and Ollama.

The bot watches one public `attempt-X` channel. Each message is scored by a local Ollama model with a nastiness / severity score from `0.0` to `1.0`. If a message crosses the configured threshold, the bot archives the current channel into a private moderator category, creates the next attempt channel, assigns configured consequence roles, logs the incident for moderators, and writes structured JSONL records that can later be used for evaluation or training.

## Features

- Watches a configured active attempt channel.
- Uses Ollama `/api/generate` in JSON mode to score messages.
- Automatically archives and replaces the channel when score crosses threshold.
- Supports tiered consequence roles.
- Optional auto-ban after configured strike and score conditions.
- Private moderator archive category.
- Moderator incident log embeds.
- Manual `/nuke` command.
- Manual context menu commands:
  - `Nuke Attempt`
  - `Silent Nuke Attempt`
- Silent nukes replace the channel without incrementing attempts, strikes, or role tiers.
- JSONL dataset logging for future task-specific model training.
- Moderator labeling and appeal-result commands.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install and run Ollama:

```bash
ollama serve
ollama pull llama3.1:8b
```

Copy the config template:

```bash
cp config.example.json config.json
```

Then edit `config.json` and fill in real Discord IDs.

## Discord Developer Portal settings

Enable these privileged intents for the bot application:

- Server Members Intent
- Message Content Intent

Invite the bot with permissions like:

- View Channels
- Send Messages
- Read Message History
- Manage Channels
- Manage Roles
- Manage Messages
- Ban Members, only if auto-ban is enabled

The bot's highest role must be above the consequence roles it assigns.

## Running

```bash
python bot.py
```

The bot creates `state.json` on first run.

## Slash commands

### `/nuke`

```text
/nuke message:<message-id-or-link> silent:false
```

Archives the active attempt channel, creates the next attempt channel, increments the attempt number, increments strikes, assigns configured consequence role tier, and logs the incident.

```text
/nuke message:<message-id-or-link> silent:true
```

Archives and replaces the active channel without incrementing attempt number, strikes, or consequence role tier.

### `/attempt-state`

Shows the currently watched channel and current attempt number.

### `/set-attempt-channel`

Sets the active channel watched by the bot.

### `/reset-strikes`

Resets a member's strike count and removes configured consequence roles.

### `/label-incident`

Appends a moderator training label event for a message ID or link.

Valid labels are defined in `bot.py` as `VALID_LABELS`.

### `/appeal-result`

Appends an appeal result event for a message ID or link.

## Dataset logging

By default, the bot logs structured records to:

```text
data/incidents.jsonl
```

This file may contain sensitive data, including message content, user IDs, attachment URLs, model scores, moderator labels, and appeal notes.

Do not commit it to Git. The included `.gitignore` ignores `data/`, `config.json`, and `state.json`.

## Preparing training data

A helper script is included:

```bash
python tools/export_training_data.py data/incidents.jsonl data/training.jsonl
```

It merges event rows by message ID and emits rows with `text`, `label`, and `score_target` where labels are available.

## Notes

LLM moderation scores can be wrong. Start with auto-ban disabled and review the mod log manually until you understand your false-positive rate.
