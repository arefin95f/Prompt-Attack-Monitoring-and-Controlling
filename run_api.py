#!/usr/bin/env python3
"""
Run the API server for Prompt Injection Defense System
"""

import os
import sys
import uvicorn
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    print("="*60)
    print("🚀 Prompt Injection Defense System API")
    print("="*60)
    print("Starting server...")
    print("API will be available at: http://localhost:8000")
    print("Documentation: http://localhost:8000/docs")
    print("Health check: http://localhost:8000/health")
    print("="*60)
    print()
    print("⚠️  Make sure you have trained the model first:")
    print("   python main.py --step train")
    print()
    print("="*60)
    
    uvicorn.run(
        "src.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Set to False to prevent reload issues
        log_level="info",
        workers=1
    )