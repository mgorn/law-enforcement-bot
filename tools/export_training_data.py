import json
import sys
from pathlib import Path
from typing import Any


LABEL_TO_SCORE = {
    "false_positive": 0.05,
    "contextual_quote": 0.20,
    "borderline": 0.55,
    "joke_but_bad": 0.70,
    "bad": 0.85,
    "spam": 0.80,
    "scam": 0.88,
    "harassment": 0.88,
    "hate": 0.92,
    "threat": 0.95,
    "doxxing": 0.98,
    "sexual": 0.90,
    "severe_banworthy": 1.00,
    "other": 0.50,
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise RuntimeError(f"Invalid JSON on line {line_number}: {error}") from error

    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: python tools/export_training_data.py <incidents.jsonl> <training.jsonl>")
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    rows = read_jsonl(input_path)
    by_message: dict[str, dict[str, Any]] = {}

    for row in rows:
        message_id = row.get("message_id")

        if not message_id:
            continue

        record = by_message.setdefault(str(message_id), {})
        event_type = row.get("event_type")

        if event_type in {
            "auto_trigger",
            "manual_nuke",
            "manual_silent_nuke",
            "non_triggered_sample",
        }:
            record.update(row)

        elif event_type == "moderator_label":
            record["moderator_label"] = row.get("moderator_label")
            record["moderator_notes"] = row.get("moderator_notes")
            record["label_created_at"] = row.get("created_at")

        elif event_type == "appeal_result":
            record["appeal_result"] = row.get("appeal_result")
            record["appeal_notes"] = row.get("appeal_notes")
            record["appeal_created_at"] = row.get("created_at")

    training_rows: list[dict[str, Any]] = []

    for message_id, record in by_message.items():
        text = record.get("message_content")
        label = record.get("moderator_label")

        if not text:
            continue

        if not label:
            continue

        score_target = LABEL_TO_SCORE.get(label, 0.50)

        training_rows.append(
            {
                "message_id": message_id,
                "text": text,
                "label": label,
                "score_target": score_target,
                "ollama_score": record.get("ollama_score"),
                "ollama_category": record.get("ollama_category"),
                "appeal_result": record.get("appeal_result"),
            }
        )

    write_jsonl(output_path, training_rows)
    print(f"wrote {len(training_rows)} rows to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
