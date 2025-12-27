#!/usr/bin/env python3
"""
UNSW-NB15 Network Attack Detection Model Training
================================================

Trains a machine learning model to detect network attacks using the UNSW-NB15 dataset.
The dataset contains 49 features with both benign and attack traffic samples.

Dataset: UNSW_NB15_training-set.csv (175,341 rows, 49 features)
Target: Binary classification (0=benign, 1=attack)
Output: Trained model pipeline saved to models/unsw_attack_detector.joblib

Usage:
    python3 train_unsw_nb15.py
    python3 train_unsw_nb15.py --test-size 0.3 --random-state 123
"""
import argparse
import json
import os
import sys
import warnings
from datetime import datetime
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings('ignore')


# UNSW-NB15 specific configuration
DATASET_PATH = 'UNSW_NB15_training-set.csv'
LABEL_COLUMN = 'label'  # Binary: 0=benign, 1=attack
ATTACK_CAT_COLUMN = 'attack_cat'  # Categorical attack types (dropped for binary)
ID_COLUMN = 'id'

# Columns to drop (non-predictive or target-related)
DROP_COLUMNS = [ID_COLUMN, ATTACK_CAT_COLUMN]


def load_and_preprocess_data(
    data_path: str, test_size: float = 0.2, random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Load UNSW-NB15 dataset and perform train/test split.
    
    Returns:
        X_train, X_test, y_train, y_test
    """
    print(f"Loading dataset from: {data_path}")
    
    if not os.path.exists(data_path):
        raise FileNotFoundError(
            f"Dataset not found: {data_path}\n"
            f"Please ensure UNSW_NB15_training-set.csv is in the current directory."
        )
    
    # Load data
    df = pd.read_csv(data_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Total samples: {len(df):,}")
    
    # Check label column exists
    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"Label column '{LABEL_COLUMN}' not found in dataset")
    
    # Separate features and target
    y = df[LABEL_COLUMN].astype(int)
    X = df.drop(columns=[LABEL_COLUMN] + [c for c in DROP_COLUMNS if c in df.columns])
    
    print(f"Features: {X.shape[1]} columns")
    
    # Print class distribution
    class_counts = y.value_counts().to_dict()
    print(f"\nClass distribution:")
    print(f"  Benign (0): {class_counts.get(0, 0):,} ({class_counts.get(0, 0)/len(y)*100:.1f}%)")
    print(f"  Attack (1): {class_counts.get(1, 0):,} ({class_counts.get(1, 0)/len(y)*100:.1f}%)")
    
    # Handle infinite values
    X = X.replace([np.inf, -np.inf], np.nan)
    
    # Train/test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    print(f"\nTrain set: {X_train.shape[0]:,} samples")
    print(f"Test set:  {X_test.shape[0]:,} samples")
    
    return X_train, X_test, y_train, y_test


def build_preprocessor(X: pd.DataFrame) -> ColumnTransformer:
    """
    Build preprocessing pipeline for UNSW-NB15 features.
    - Numeric columns: impute + scale
    - Categorical columns: impute + one-hot encode
    """
    numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    categorical_cols = [c for c in X.columns if c not in numeric_cols]
    
    print(f"\nFeature types:")
    print(f"  Numeric: {len(numeric_cols)} features")
    print(f"  Categorical: {len(categorical_cols)} features")
    
    # Numeric pipeline
    num_pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])
    
    # Categorical pipeline (handle sklearn version differences)
    try:
        ohe = OneHotEncoder(handle_unknown='ignore', sparse_output=True)
    except TypeError:
        ohe = OneHotEncoder(handle_unknown='ignore', sparse=True)
    
    cat_pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='constant', fill_value='unknown')),
        ('onehot', ohe)
    ])
    
    # Combined preprocessor
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', num_pipeline, numeric_cols),
            ('cat', cat_pipeline, categorical_cols)
        ],
        remainder='drop'
    )
    
    return preprocessor


def get_candidate_models(random_state: int = 42) -> Dict:
    """
    Define candidate models for evaluation.
    Including best performers: Random Forest, Gradient Boosting, Extra Trees
    """
    return {
        'random_forest': RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            class_weight='balanced',
            random_state=random_state,
            n_jobs=-1
        ),
        'gradient_boosting': GradientBoostingClassifier(
            n_estimators=100,
            max_depth=10,
            learning_rate=0.1,
            random_state=random_state
        ),
        'extra_trees': ExtraTreesClassifier(
            n_estimators=200,
            max_depth=20,
            class_weight='balanced',
            random_state=random_state,
            n_jobs=-1
        )
    }


def evaluate_model(
    pipeline: Pipeline,
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
    model_name: str
) -> Dict:
    """
    Train and evaluate a model pipeline.
    
    Returns:
        Dictionary with evaluation metrics
    """
    print(f"\n{'='*70}")
    print(f"Training: {model_name}")
    print('='*70)
    
    # Train
    pipeline.fit(X_train, y_train)
    
    # Predict
    y_pred = pipeline.predict(X_test)
    
    # Get probabilities if available
    y_prob = None
    try:
        if hasattr(pipeline.named_steps['model'], 'predict_proba'):
            y_prob = pipeline.predict_proba(X_test)[:, 1]
    except Exception:
        pass
    
    # Calculate metrics
    metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1': float(f1_score(y_test, y_pred, zero_division=0)),
    }
    
    # ROC-AUC if probabilities available
    if y_prob is not None and len(np.unique(y_test)) == 2:
        try:
            metrics['roc_auc'] = float(roc_auc_score(y_test, y_prob))
        except Exception:
            metrics['roc_auc'] = None
    else:
        metrics['roc_auc'] = None
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    metrics['confusion_matrix'] = cm.tolist()
    
    # Classification report
    metrics['classification_report'] = classification_report(
        y_test, y_pred, target_names=['Benign', 'Attack'], zero_division=0
    )
    
    # Print results
    print(f"\nResults:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    if metrics['roc_auc'] is not None:
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
    
    print(f"\nConfusion Matrix:")
    print(f"  TN: {cm[0][0]:,}  |  FP: {cm[0][1]:,}")
    print(f"  FN: {cm[1][0]:,}  |  TP: {cm[1][1]:,}")
    
    return metrics


def select_best_model(results: Dict) -> str:
    """
    Select best model based on F1 score (primary) and ROC-AUC (secondary).
    """
    best_name = None
    best_score = (-1, -1)
    
    for name, metrics in results.items():
        score = (metrics['f1'], metrics.get('roc_auc', -1))
        if score > best_score:
            best_score = score
            best_name = name
    
    return best_name


def save_model_and_report(
    pipeline: Pipeline,
    results: Dict,
    best_model_name: str,
    output_dir: str = 'models'
):
    """
    Save trained model and evaluation report with permission fallback.
    """
    def try_save(dir_path):
        os.makedirs(dir_path, exist_ok=True)
        model_path = os.path.join(dir_path, 'unsw_attack_detector.joblib')
        joblib.dump(pipeline, model_path)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'dataset': DATASET_PATH,
            'best_model': best_model_name,
            'all_results': results,
            'model_path': model_path
        }
        
        report_path = os.path.join(dir_path, 'unsw_training_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return model_path, report_path
    
    # Try primary output directory
    try:
        model_path, report_path = try_save(output_dir)
    except PermissionError:
        print(f"\n[WARN] Permission denied for '{output_dir}'. Using fallback directory.")
        fallback_dir = os.path.join(os.getcwd(), 'trained_models')
        model_path, report_path = try_save(fallback_dir)
    
    print(f"\n✓ Model saved to: {model_path}")
    print(f"✓ Report saved to: {report_path}")
    
    # Print final summary
    print(f"\n{'='*70}")
    print("TRAINING COMPLETE")
    print('='*70)
    print(f"Best Model: {best_model_name}")
    print(f"F1 Score:   {results[best_model_name]['f1']:.4f}")
    print(f"Accuracy:   {results[best_model_name]['accuracy']:.4f}")
    if results[best_model_name]['roc_auc']:
        print(f"ROC-AUC:    {results[best_model_name]['roc_auc']:.4f}")
    print('='*70)
    
    return model_path, report_path


def main():
    parser = argparse.ArgumentParser(
        description='Train UNSW-NB15 attack detection model'
    )
    parser.add_argument(
        '--data-path',
        default=DATASET_PATH,
        help=f'Path to UNSW-NB15 training CSV (default: {DATASET_PATH})'
    )
    parser.add_argument(
        '--test-size',
        type=float,
        default=0.2,
        help='Test set fraction (default: 0.2)'
    )
    parser.add_argument(
        '--random-state',
        type=int,
        default=42,
        help='Random seed (default: 42)'
    )
    parser.add_argument(
        '--output-dir',
        default='models',
        help='Output directory for model and report (default: models)'
    )
    args = parser.parse_args()
    
    print("="*70)
    print("UNSW-NB15 Network Attack Detection Model Training")
    print("="*70)
    
    # Load data
    X_train, X_test, y_train, y_test = load_and_preprocess_data(
        args.data_path, args.test_size, args.random_state
    )
    
    # Build preprocessor
    preprocessor = build_preprocessor(X_train)
    
    # Get candidate models
    models = get_candidate_models(args.random_state)
    
    # Train and evaluate each model
    results = {}
    trained_pipelines = {}
    
    for name, model in models.items():
        pipeline = Pipeline([
            ('preprocessor', preprocessor),
            ('model', model)
        ])
        
        metrics = evaluate_model(
            pipeline, X_train, X_test, y_train, y_test, name
        )
        results[name] = metrics
        trained_pipelines[name] = pipeline
    
    # Select best model
    best_name = select_best_model(results)
    best_pipeline = trained_pipelines[best_name]
    
    # Retrain best model on full dataset (train + test)
    print(f"\n{'='*70}")
    print(f"Retraining best model ({best_name}) on full dataset...")
    print('='*70)
    
    X_full = pd.concat([X_train, X_test], axis=0)
    y_full = pd.concat([y_train, y_test], axis=0)
    best_pipeline.fit(X_full, y_full)
    print("✓ Retraining complete")
    
    # Save model and report
    model_path, report_path = save_model_and_report(
        best_pipeline, results, best_name, args.output_dir
    )
    
    print("\n✓ All done! Training completed successfully!")
    print(f"\nTo use the model:")
    print(f"  import joblib")
    print(f"  model = joblib.load('{model_path}')")
    print(f"  predictions = model.predict(X_new)")


if __name__ == '__main__':
    main()
