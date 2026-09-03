"""
Phase 5: Structured decision logging for upgrade observability.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class DecisionLogger:
    def __init__(self, log_path: str = "logs/decisions.jsonl", enabled: bool = True):
        self.enabled = enabled
        self.log_path = Path(log_path)
        if enabled:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                logger.warning("Decision logger path issue: %s", exc)
                self.enabled = False

    def log(self, event: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            **event,
        }
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning("Failed to write decision log: %s", exc)
