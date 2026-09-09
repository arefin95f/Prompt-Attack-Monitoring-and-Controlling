"""
LAYER 2: NLP CLASSIFIER ENSEMBLE - COMPLETE WORKING VERSION
"""

import joblib
import numpy as np
import logging
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, f1_score
from typing import Dict, List, Optional
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Layer2Classifier:
    def __init__(self, model_dir: str = "./models/detector", max_features: int = 15000, ngram_range: tuple = (1, 2)):
        self.model_dir = model_dir
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.vectorizer = None
        self.models = {}
        self.is_trained = False
    
    def train(
        self,
        X_train: List[str],
        y_train: List[int],
        sample_weight: Optional[List[float]] = None,
    ) -> Dict:
        logger.info("="*60)
        logger.info("LAYER 2: TRAINING")
        logger.info(f"Samples: {len(X_train)}")
        if sample_weight is not None:
            import numpy as np
            w = np.asarray(sample_weight, dtype=float)
            team_n = int((w > 1.0).sum())
            logger.info(f"Team-weighted rows: {team_n} (max weight={float(w.max()):.1f})")
        logger.info("="*60)
        
        self.vectorizer = TfidfVectorizer(
            max_features=self.max_features,
            ngram_range=self.ngram_range,
            stop_words='english',
            max_df=0.9,
            min_df=3,
            sublinear_tf=True
        )
        
        X_train_vec = self.vectorizer.fit_transform(X_train)
        logger.info(f"Features: {X_train_vec.shape[1]}")
        
        fit_kw = {}
        if sample_weight is not None:
            fit_kw["sample_weight"] = sample_weight
        
        models = {
            'logistic': LogisticRegression(C=1.0, max_iter=1000, class_weight='balanced', random_state=42, n_jobs=-1),
            'random_forest': RandomForestClassifier(n_estimators=100, max_depth=10, class_weight='balanced', random_state=42, n_jobs=-1),
            'xgboost': XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, use_label_encoder=False, eval_metric='logloss', verbosity=0, n_jobs=-1),
            'svm': LinearSVC(C=1.0, class_weight='balanced', max_iter=2000, random_state=42, dual='auto')
        }
        
        results = {}
        for name, model in models.items():
            try:
                model.fit(X_train_vec, y_train, **fit_kw)
                self.models[name] = model
                preds = model.predict(X_train_vec)
                acc = accuracy_score(y_train, preds)
                f1 = f1_score(y_train, preds, average='weighted')
                results[name] = {'accuracy': acc, 'f1': f1}
                logger.info(f"  {name}: Acc={acc:.4f}, F1={f1:.4f}")
            except Exception as e:
                logger.error(f"  {name} failed: {e}")
        
        self.is_trained = bool(self.models)
        if self.is_trained:
            self.save()
        return results
    
    def predict(self, texts: List[str]) -> Dict:
        if not self.is_trained or not self.models:
            return self._empty_result(texts)
        
        try:
            X_vec = self.vectorizer.transform(texts)
        except:
            return self._empty_result(texts)
        
        predictions = []
        probabilities = []
        individual_risks = {}
        
        for name, model in self.models.items():
            try:
                if hasattr(model, 'predict_proba'):
                    prob = model.predict_proba(X_vec)
                    pred = model.predict(X_vec)
                else:
                    pred = model.predict(X_vec)
                    decision = model.decision_function(X_vec)
                    prob = np.column_stack([1/(1+np.exp(decision)), np.exp(decision)/(1+np.exp(decision))])
            except:
                continue
            
            predictions.append(pred)
            probabilities.append(prob)
            individual_risks[name] = prob[:, 1].tolist()
        
        if not probabilities:
            return self._empty_result(texts)
        
        avg_probs = np.mean(probabilities, axis=0)
        
        # ============================================================
        # ATTACK TYPE DETECTION - COMPLETE & WORKING
        # ============================================================
        attack_types = [self._detect_attack_type(text) for text in texts]
        attack_categories = [self._detect_attack_categories(text) for text in texts]
        
        return {
            'predictions': [int(p) for p in np.argmax(avg_probs, axis=1)],
            'risk_scores': avg_probs[:, 1].tolist(),
            'probabilities': avg_probs.tolist(),
            'individual_risks': individual_risks,
            'attack_types': attack_types,
            'attack_categories': attack_categories,
            'num_models': len(probabilities)
        }
    
    # ============================================================
    # COMPLETE ATTACK TYPE DETECTION
    # ============================================================
    
    def _detect_attack_type(self, text: str) -> str:
        """Detect the attack type from the prompt (scored, not first-match)."""
        try:
            from src.layers.attack_typer import AttackTypeDetector
            return AttackTypeDetector().detect_type(text)
        except Exception:
            return "unknown"
    
    def _detect_attack_categories(self, text: str) -> List[str]:
        """Detect all attack categories present."""
        try:
            from src.layers.attack_typer import AttackTypeDetector
            result = AttackTypeDetector().detect(text)
            cats = result.get("categories") or []
            return cats if cats else (["unknown"] if result.get("attack_type") == "unknown" else [result["attack_type"]])
        except Exception:
            return ["unknown"]
    
    def _empty_result(self, texts: List[str]) -> Dict:
        return {
            'predictions': [0] * len(texts),
            'risk_scores': [0.0] * len(texts),
            'probabilities': [[0.5, 0.5] for _ in texts],
            'individual_risks': {},
            'attack_types': ['unknown'] * len(texts),
            'attack_categories': [['unknown'] for _ in texts],
            'num_models': 0
        }
    
    def save(self):
        import os
        os.makedirs(self.model_dir, exist_ok=True)
        joblib.dump(self.vectorizer, f"{self.model_dir}/vectorizer.pkl")
        for name, model in self.models.items():
            joblib.dump(model, f"{self.model_dir}/{name}.pkl")
    
    def load(self):
        import os
        self.vectorizer = joblib.load(f"{self.model_dir}/vectorizer.pkl")
        self.models = {}
        model_names = ['logistic', 'random_forest', 'xgboost', 'svm']
        for name in model_names:
            try:
                self.models[name] = joblib.load(f"{self.model_dir}/{name}.pkl")
            except:
                pass
        self.is_trained = bool(self.models)
        return self.is_trained