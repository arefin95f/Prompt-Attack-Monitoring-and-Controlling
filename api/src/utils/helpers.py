"""
Helper utility functions
"""

import json
import logging
import yaml
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional


def setup_logging(log_file: str = "logs/app.log", level: str = "INFO"):
    """Setup logging configuration."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)


def get_timestamp() -> str:
    """Get current timestamp as string."""
    return datetime.now().isoformat()


def ensure_dir(path: Path) -> Path:
    """Ensure directory exists."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_json_load(file_path: Path) -> Optional[Dict]:
    """Safely load JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading {file_path}: {e}")
        return None


def safe_json_dump(data: Any, file_path: Path, indent: int = 2) -> bool:
    """Safely save JSON file."""
    try:
        ensure_dir(file_path.parent)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return True
    except Exception as e:
        logging.error(f"Error saving {file_path}: {e}")
        return False


def load_config(config_path: Path) -> Dict:
    """Load YAML configuration file."""
    if not config_path.exists():
        return {}
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Error loading config {config_path}: {e}")
        return {}


def save_config(config: Dict, config_path: Path) -> bool:
    """Save YAML configuration file."""
    try:
        ensure_dir(config_path.parent)
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        return True
    except Exception as e:
        logging.error(f"Error saving config {config_path}: {e}")
        return False


def get_file_size(file_path: Path) -> str:
    """Get human-readable file size."""
    if not file_path.exists():
        return "0 B"
    
    size = file_path.stat().st_size
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to maximum length."""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def clean_text(text: str) -> str:
    """Clean text by removing excessive whitespace."""
    return ' '.join(text.split())


def is_valid_prompt(text: str) -> bool:
    """Check if prompt is valid (not empty, not too short)."""
    return bool(text and len(text.strip()) > 2)


def extract_keywords(text: str, max_keywords: int = 10) -> list:
    """Extract important keywords from text."""
    from sklearn.feature_extraction.text import CountVectorizer
    
    # Simple keyword extraction using TF
    vectorizer = CountVectorizer(
        max_features=max_keywords,
        stop_words='english',
        ngram_range=(1, 2)
    )
    
    try:
        X = vectorizer.fit_transform([text])
        feature_names = vectorizer.get_feature_names_out()
        scores = X.toarray()[0]
        
        # Sort by score
        keywords = sorted(
            zip(feature_names, scores),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [kw for kw, score in keywords if score > 0]
    except:
        return text.split()[:max_keywords]
