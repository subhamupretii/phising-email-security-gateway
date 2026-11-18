"""Train a local machine learning phishing detection model.

This script trains a Naive Bayes classifier using TF-IDF features on email text.
The trained model is serialized to phishing_model.joblib for use by the gateway.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

# Paths relative to this script
SCRIPT_DIR = Path(__file__).parent
DATASET_PATH = SCRIPT_DIR / "phishing_dataset.csv"
MODEL_PATH = SCRIPT_DIR / "phishing_model.joblib"


def load_dataset(dataset_path: Path = DATASET_PATH) -> pd.DataFrame:
    """Load the phishing dataset from CSV, with synthetic fallback if missing."""
    if dataset_path.exists():
        print(f"Loading dataset from {dataset_path}")
        return pd.read_csv(dataset_path, on_bad_lines='warn')
    else:
        print(f"Dataset not found at {dataset_path}, creating synthetic fallback...")
        synthetic_data = {
            "text": [
                "Dear Team, Please find attached the quarterly financial report. Best regards, John",
                "URGENT: Your account will be suspended unless you verify immediately. Click here",
                "Hi Sarah, The meeting has been moved to 3 PM. Thanks, Mike",
                "ALERT: Suspicious activity detected. Confirm your password now or lose access",
                "Hello, The office will be closed Monday for the holiday. HR Department",
                "Your password has expired. Reset it immediately or account will be locked",
                "Good morning, Your order has been shipped. Tracking number: ABC123",
                "FINAL WARNING: Your account will be deleted within 24 hours. Act now",
                "Team, Don't forget to submit your timesheets by Friday. Management",
                "Security Alert: Unrecognized login detected. Verify your identity",
            ],
            "label": [0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
        }
        df = pd.DataFrame(synthetic_data)
        # Save synthetic dataset for future use
        df.to_csv(dataset_path, index=False, quoting=1)
        print(f"Synthetic dataset saved to {dataset_path}")
        return df


def train_model(df: pd.DataFrame) -> Pipeline:
    """Train a Naive Bayes classifier with TF-IDF vectorization."""
    print(f"Training model on {len(df)} samples...")
    print(f"Class distribution: {df['label'].value_counts().to_dict()}")

    X = df["text"].astype(str)
    y = df["label"]

    # Split data for evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Build pipeline: TF-IDF vectorizer + Naive Bayes classifier
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    stop_words="english",
                    max_features=5000,
                    ngram_range=(1, 2),
                    lowercase=True,
                ),
            ),
            ("classifier", MultinomialNB()),
        ]
    )

    # Train the model
    pipeline.fit(X_train, y_train)

    # Evaluate on test set
    y_pred = pipeline.predict(X_test)
    print("\nModel Evaluation:")
    print(classification_report(y_test, y_pred, target_names=["Clean", "Phishing"]))

    return pipeline


def save_model(pipeline: Pipeline, model_path: Path = MODEL_PATH) -> None:
    """Serialize the trained model to disk."""
    print(f"Saving trained model to {model_path}")
    joblib.dump(pipeline, model_path)
    print("Model saved successfully.")


def main() -> None:
    """Main training pipeline."""
    print("=" * 60)
    print("Phishing Email ML Model Training")
    print("=" * 60)

    # Load dataset
    df = load_dataset()

    if len(df) < 10:
        print("ERROR: Dataset too small for training. Need at least 10 samples.")
        sys.exit(1)

    # Train model
    pipeline = train_model(df)

    # Save model
    save_model(pipeline)

    print("\n" + "=" * 60)
    print("Training complete. Model ready for gateway integration.")
    print("=" * 60)


if __name__ == "__main__":
    main()
