"""
Data loader for prompt injection datasets
"""

import json
import hashlib
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PromptSample:
    """Unified prompt sample format."""
    text: str
    label: int  # 0=benign, 1=malicious
    attack_category: Optional[str] = None
    severity: Optional[str] = None
    group_id: Optional[str] = None
    source: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)


class DatasetLoader:
    """Loads and processes prompt injection datasets."""
    
    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        
        self.samples: List[PromptSample] = []
    
    def explore_files(self):
        """Explore data files in raw directory."""
        files = list(self.raw_dir.glob("*"))
        if not files:
            logger.warning("No files found in data/raw/")
            return
        
        logger.info("\nData files found:")
        for file_path in files:
            if file_path.name.startswith('.'):
                continue
            logger.info(f"  - {file_path.name}")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('{'):
                        data = json.loads(first_line)
                        logger.info(f"     Keys: {list(data.keys())}")
                        text = data.get('text', data.get('payload', 'N/A'))
                        logger.info(f"     Text preview: {str(text)[:80]}...")
            except Exception as e:
                logger.warning(f"     Error reading: {e}")
    
    def load_jayavibhav(self) -> List[PromptSample]:
        """Load jayavibhav prompt injection dataset."""
        samples = []
        file_path = self.raw_dir / "jayavibhav_prompt_injection.jsonl"
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return samples
        
        logger.info(f"Loading {file_path.name}...")
        
        # Use utf-8-sig to handle BOM if present
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            lines = f.readlines()
            total = len(lines)
            logger.info(f"  Total lines: {total}")
            
            for i, line in enumerate(lines):
                try:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    text = data.get('text', '')
                    if not text:
                        continue
                    
                    label = data.get('label', 0)
                    if isinstance(label, str):
                        label = 1 if label.lower() in ['malicious', '1', 'true'] else 0
                    elif isinstance(label, bool):
                        label = 1 if label else 0
                    else:
                        label = int(label) if label is not None else 0
                    
                    attack_category = self._classify_attack(text) if label == 1 else None
                    
                    samples.append(PromptSample(
                        text=text,
                        label=label,
                        attack_category=attack_category,
                        source="jayavibhav",
                        group_id=f"jay_{hashlib.md5(text.encode('utf-8')).hexdigest()[:10]}"
                    ))
                except (json.JSONDecodeError, Exception):
                    continue
                
                if (i + 1) % 50000 == 0:
                    logger.info(f"  Processed {i+1} lines...")
        
        logger.info(f"Loaded {len(samples)} samples from jayavibhav")
        return samples
    
    def load_moltbook(self) -> List[PromptSample]:
        """Load moltbook extended dataset."""
        samples = []
        file_path = self.raw_dir / "moltbook_extended.jsonl"
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return samples
        
        logger.info(f"Loading {file_path.name}...")
        
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            lines = f.readlines()
            total = len(lines)
            logger.info(f"  Total lines: {total}")
            
            for i, line in enumerate(lines):
                try:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    
                    text = data.get('payload', '')
                    if not text:
                        text = data.get('text', data.get('prompt', ''))
                    if not text:
                        continue
                    
                    label = 0
                    categories = str(data.get('categories', '')).lower()
                    keywords = str(data.get('keywords', '')).lower()
                    wrapper = str(data.get('wrapper', '')).lower()
                    
                    injection_indicators = [
                        'injection', 'jailbreak', 'attack', 'malicious',
                        'override', 'ignore', 'bypass', 'disregard', 'forget'
                    ]
                    
                    combined = f"{categories} {keywords} {wrapper}"
                    if any(ind in combined for ind in injection_indicators):
                        label = 1
                    
                    text_lower = text.lower()
                    if any(ind in text_lower for ind in ['ignore previous', 'forget all', 'bypass safety']):
                        label = 1
                    
                    attack_category = self._classify_attack(text) if label == 1 else None
                    
                    samples.append(PromptSample(
                        text=text,
                        label=label,
                        attack_category=attack_category,
                        source="moltbook",
                        group_id=f"molt_{data.get('id', hashlib.md5(text.encode('utf-8')).hexdigest()[:10])}"
                    ))
                except (json.JSONDecodeError, Exception):
                    continue
                
                if (i + 1) % 1000 == 0:
                    logger.info(f"  Processed {i+1} lines...")
        
        logger.info(f"Loaded {len(samples)} samples from moltbook")
        return samples
    
    def _classify_attack(self, text: str) -> str:
        """Heuristically classify attack type."""
        text_lower = text.lower()
        
        patterns = {
            "direct_injection": ['ignore', 'forget', 'override', 'disregard', 'bypass'],
            "jailbreak": ['dan', 'jailbreak', 'developer mode', 'do anything', 'unrestricted'],
            "system_extraction": ['system prompt', 'configuration', 'internal rules', 'safety guidelines'],
            "data_extraction": ['extract', 'reveal', 'expose', 'list all', 'output all'],
            "tool_injection": ['execute', 'function', 'api call', 'sql', 'run command'],
            "context_poisoning": ['remember', 'adopt', 'persona', 'pretend', 'role-play'],
            "obfuscation": ['base64', 'rot13', 'encoded', 'decode', 'hex'],
            "multi_turn": ['first', 'then', 'step', 'gradually', 'next']
        }
        
        for category, keywords in patterns.items():
            if any(kw in text_lower for kw in keywords):
                return category
        return "unknown"
    
    def build_dataset(self) -> Tuple[List[PromptSample], Dict]:
        """Build unified dataset."""
        all_samples = []
        stats = {}
        
        jay_samples = self.load_jayavibhav()
        if jay_samples:
            all_samples.extend(jay_samples)
            stats['jayavibhav'] = len(jay_samples)
        
        molt_samples = self.load_moltbook()
        if molt_samples:
            all_samples.extend(molt_samples)
            stats['moltbook'] = len(molt_samples)
        
        if not all_samples:
            logger.error("No samples loaded!")
            return [], stats
        
        unique_samples = []
        seen_texts = set()
        for sample in all_samples:
            key = hashlib.md5(sample.text[:100].encode('utf-8')).hexdigest()
            if key not in seen_texts:
                seen_texts.add(key)
                unique_samples.append(sample)
        
        stats['total'] = len(unique_samples)
        stats['malicious'] = sum(1 for s in unique_samples if s.label == 1)
        stats['benign'] = sum(1 for s in unique_samples if s.label == 0)
        
        self.samples = unique_samples
        logger.info(f"\nBuilt dataset: {len(unique_samples)} samples")
        logger.info(f"   Malicious: {stats['malicious']}")
        logger.info(f"   Benign: {stats['benign']}")
        
        return unique_samples, stats
    
    def save_splits(self, samples: Optional[List[PromptSample]] = None) -> Dict:
        """Save train/val/test splits."""
        if samples is None:
            samples = self.samples
        
        if not samples:
            logger.error("No samples to save!")
            return {}
        
        groups = {}
        for sample in samples:
            gid = sample.group_id or f"group_{hashlib.md5(sample.text.encode('utf-8')).hexdigest()[:10]}"
            if gid not in groups:
                groups[gid] = []
            groups[gid].append(sample)
        
        group_ids = list(groups.keys())
        
        train_ids, temp_ids = train_test_split(group_ids, test_size=0.3, random_state=42)
        val_ids, test_ids = train_test_split(temp_ids, test_size=0.5, random_state=42)
        
        splits = {"train": [], "val": [], "test": []}
        
        for gid in train_ids:
            splits["train"].extend(groups[gid])
        for gid in val_ids:
            splits["val"].extend(groups[gid])
        for gid in test_ids:
            splits["test"].extend(groups[gid])
        
        for name, split_samples in splits.items():
            file_path = self.processed_dir / f"{name}.jsonl"
            with open(file_path, 'w', encoding='utf-8') as f:
                for sample in split_samples:
                    f.write(json.dumps(sample.to_dict(), ensure_ascii=False) + '\n')
            logger.info(f"Saved {len(split_samples)} samples to {name}.jsonl")
        
        stats = {
            "train": len(splits["train"]),
            "val": len(splits["val"]),
            "test": len(splits["test"]),
            "total": len(samples),
            "malicious": sum(1 for s in samples if s.label == 1),
            "benign": sum(1 for s in samples if s.label == 0)
        }
        
        with open(self.processed_dir / "stats.json", 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        
        return stats