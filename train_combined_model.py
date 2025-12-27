#!/usr/bin/env python3
"""
Combined Network Attack Detection Model Training - Google Colab Version
=======================================================================

Trains a model using both UNSW-NB15 and Bot-IoT datasets with ALL features.
Uses actual dataset values, no artificial defaults or zeros.

For Google Colab:
1. Upload UNSW_NB15_training-set.csv
2. Upload Bot_IoT folder with all data_*.csv files
3. Run this script

Usage:
    python3 train_combined_model.py
"""
import glob
import json
import os
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.impute import SimpleImputer
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
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore')

def load_unsw_nb15(file_path: str) -> pd.DataFrame:
    """Load UNSW-NB15 dataset with ALL features."""
    print(f"Loading UNSW-NB15 from: {file_path}")
    df = pd.read_csv(file_path)
    
    # Drop only non-predictive columns
    drop_cols = ['id', 'attack_cat']  # Keep everything else
    df = df.drop(columns=[c for c in drop_cols if c in df.columns])
    
    # Separate features and label
    y = df['label'].astype(int)
    X = df.drop(columns=['label'])
    
    print(f"  Loaded: {len(df):,} rows")
    print(f"  Features: {len(X.columns)} columns")
    print(f"  Attacks: {y.sum():,} ({y.sum()/len(y)*100:.1f}%)")
    
    df['dataset'] = 'UNSW-NB15'
    return df

def load_bot_iot_all_files(folder_path: str) -> pd.DataFrame:
    """Load ALL Bot-IoT dataset files with ALL features."""
    print(f"Loading Bot-IoT from: {folder_path}")
    
    csv_files = sorted(glob.glob(os.path.join(folder_path, "data_*.csv")))
    print(f"  Found {len(csv_files)} CSV files")
    print(f"  Loading ALL files (this will take time)...")
    
    dfs = []
    total_rows = 0
    
    for i, file in enumerate(csv_files, 1):
        try:
            # Read with all columns
            df_chunk = pd.read_csv(file, low_memory=False)
            total_rows += len(df_chunk)
            
            # Convert attack column to binary label
            if 'attack' in df_chunk.columns:
                df_chunk['label'] = (df_chunk['attack'] == 1).astype(int)
            elif 'category' in df_chunk.columns:
                df_chunk['label'] = (df_chunk['category'].str.lower() != 'normal').astype(int)
            else:
                print(f"    Warning: No attack/category column in {file}")
                continue
            
            # Drop non-predictive columns
            drop_cols = ['pkSeqID', 'stime', 'ltime', 'saddr', 'daddr', 'smac', 'dmac', 
                        'soui', 'doui', 'attack', 'category', 'subcategory']
            df_chunk = df_chunk.drop(columns=[c for c in drop_cols if c in df_chunk.columns])
            
            dfs.append(df_chunk)
            
            if i % 10 == 0 or i == len(csv_files):
                print(f"    Processed {i}/{len(csv_files)} files ({total_rows:,} rows)")
                
        except Exception as e:
            print(f"    Error reading {file}: {e}")
            continue
    
    if not dfs:
        raise ValueError("No Bot-IoT data loaded successfully")
    
    df = pd.concat(dfs, ignore_index=True)
    
    print(f"  Total Bot-IoT: {len(df):,} rows")
    print(f"  Features: {len(df.columns)-1} columns")
    print(f"  Attacks: {df['label'].sum():,} ({df['label'].sum()/len(df)*100:.1f}%)")
    
    df['dataset'] = 'Bot-IoT'
    return df

def align_datasets(df_unsw: pd.DataFrame, df_bot: pd.DataFrame) -> tuple:
    """Align datasets by common columns only."""
    print("\n" + "="*80)
    print("ALIGNING DATASETS")
    print("="*80)
    
    # Get column sets (excluding label and dataset)
    unsw_cols = set(df_unsw.columns) - {'label', 'dataset'}
    bot_cols = set(df_bot.columns) - {'label', 'dataset'}
    
    # Find common columns
    common_cols = unsw_cols & bot_cols
    print(f"UNSW-NB15 unique features: {len(unsw_cols)}")
    print(f"Bot-IoT unique features: {len(bot_cols)}")
    print(f"Common features: {len(common_cols)}")
    print(f"Common features: {sorted(common_cols)}")
    
    # Keep only common features + label
    df_unsw_aligned = df_unsw[list(common_cols) + ['label']].copy()
    df_bot_aligned = df_bot[list(common_cols) + ['label']].copy()
    
    return df_unsw_aligned, df_bot_aligned

def prepare_combined_dataset(unsw_path: str, bot_iot_path: str) -> tuple:
    """Load and combine both datasets."""
    print("\n" + "="*80)
    print("LOADING DATASETS")
    print("="*80)
    
    # Load full datasets
    df_unsw = load_unsw_nb15(unsw_path)
    df_bot = load_bot_iot_all_files(bot_iot_path)
    
    # Align by common columns
    df_unsw_aligned, df_bot_aligned = align_datasets(df_unsw, df_bot)
    
    # Combine
    df = pd.concat([df_unsw_aligned, df_bot_aligned], ignore_index=True)
    
    print(f"\n" + "="*80)
    print("COMBINED DATASET")
    print("="*80)
    print(f"Total samples: {len(df):,} rows")
    print(f"  UNSW-NB15: {len(df_unsw_aligned):,} ({len(df_unsw_aligned)/len(df)*100:.1f}%)")
    print(f"  Bot-IoT:   {len(df_bot_aligned):,} ({len(df_bot_aligned)/len(df)*100:.1f}%)")
    print(f"Total features: {len(df.columns)-1}")
    print(f"Total attacks: {df['label'].sum():,} ({df['label'].sum()/len(df)*100:.1f}%)")
    
    # Prepare X, y
    X = df.drop(columns=['label'])
    y = df['label'].astype(int)
    
    # Handle infinite values (replace with NaN, imputer will handle)
    X = X.replace([np.inf, -np.inf], np.nan)
    
    return X, y

def train_model(X_train, X_test, y_train, y_test):
    """Train Gradient Boosting model."""
    print("\n" + "="*80)
    print("TRAINING MODEL")
    print("="*80)
    
    # Pipeline: Impute NaN with median, then scale, then classify
    pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),  # Only imputes NaN/missing
        ('scaler', StandardScaler()),
        ('classifier', GradientBoostingClassifier(
            n_estimators=500,
            learning_rate=0.05,
            max_depth=7,
            min_samples_split=100,
            min_samples_leaf=50,
            subsample=0.8,
            max_features='sqrt',
            random_state=42,
            verbose=1
        ))
    ])
    
    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples: {len(X_test):,}")
    print(f"Features: {list(X_train.columns)}")
    print(f"\nTraining Gradient Boosting (500 estimators)...")
    
    pipeline.fit(X_train, y_train)
    
    print("\n" + "="*80)
    print("EVALUATION")
    print("="*80)
    
    # Training metrics
    y_train_pred = pipeline.predict(X_train)
    train_acc = accuracy_score(y_train, y_train_pred)
    print(f"Training Accuracy: {train_acc:.4f}")
    
    # Test predictions
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    
    # Metrics
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1_score': f1_score(y_test, y_pred),
        'roc_auc': roc_auc_score(y_test, y_proba),
        'train_accuracy': train_acc
    }
    
    print(f"\nTest Set Performance:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1-Score:  {metrics['f1_score']:.4f}")
    print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
    
    print(f"\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]:,}  FP={cm[0,1]:,}")
    print(f"  FN={cm[1,0]:,}  TP={cm[1,1]:,}")
    
    return pipeline, metrics

def main():
    """Main training workflow."""
    print("\n" + "="*80)
    print("FULL DATASET TRAINING - UNSW-NB15 + BOT-IOT")
    print("="*80)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Note: Using ALL features and ALL data files")
    print("      No artificial zeros or defaults - only actual dataset values")
    
    # Paths
    unsw_path = 'UNSW_NB15_training-set.csv'
    bot_iot_path = 'Bot_IoT'
    model_dir = Path('trained_models')
    model_dir.mkdir(exist_ok=True)
    
    # Load and combine datasets
    X, y = prepare_combined_dataset(unsw_path, bot_iot_path)
    
    # Train/test split
    print("\n" + "="*80)
    print("SPLITTING DATA")
    print("="*80)
    print("Split ratio: 80% train, 20% test")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  Training: {len(X_train):,} samples")
    print(f"  Testing:  {len(X_test):,} samples")
    
    # Train model
    model, metrics = train_model(X_train, X_test, y_train, y_test)
    
    # Save model
    model_path = model_dir / 'unsw_attack_detector.joblib'
    print(f"\n" + "="*80)
    print("SAVING MODEL")
    print("="*80)
    print(f"Saving to: {model_path}")
    joblib.dump(model, model_path)
    
    # Save training report
    report = {
        'model_type': 'Gradient Boosting Classifier',
        'datasets': ['UNSW-NB15 (Full)', 'Bot-IoT (All Files)'],
        'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'features': list(X.columns),
        'n_features': len(X.columns),
        'training_samples': len(X_train),
        'testing_samples': len(X_test),
        'metrics': metrics,
        'model_path': str(model_path),
        'notes': 'Trained with ALL features, no artificial defaults'
    }
    
    report_path = model_dir / 'unsw_training_report.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Report saved to: {report_path}")
    print("\n" + "="*80)
    print("TRAINING COMPLETE!")
    print("="*80)
    print(f"Final Accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"Download '{model_path}' and use for live detection")

if __name__ == "__main__":
    main()

def load_unsw_nb15(file_path: str, sample_size: int = None) -> pd.DataFrame:
    """Load and preprocess UNSW-NB15 dataset."""
    print(f"Loading UNSW-NB15 from: {file_path}")
    df = pd.read_csv(file_path)
    
    if sample_size and len(df) > sample_size:
        # Stratified sampling
        df = df.groupby('label', group_keys=False).apply(
            lambda x: x.sample(min(len(x), sample_size // 2), random_state=42)
        ).reset_index(drop=True)
    
    # Keep only common features + label
    keep_cols = [c for c in COMMON_FEATURES if c in df.columns] + ['label']
    df = df[keep_cols].copy()
    
    # Compute missing features from UNSW data
    if 'srate' not in df.columns and 'sbytes' in df.columns and 'dur' in df.columns:
        df['srate'] = df['sbytes'] / (df['dur'] + 0.001)
    if 'drate' not in df.columns and 'dbytes' in df.columns and 'dur' in df.columns:
        df['drate'] = df['dbytes'] / (df['dur'] + 0.001)
    if 'mean' not in df.columns:
        # Average of source and dest mean
        if 'smean' in df.columns and 'dmean' in df.columns:
            df['mean'] = (df['smean'] + df['dmean']) / 2
        else:
            df['mean'] = 0
    
    # Add missing columns with defaults
    for col in COMMON_FEATURES:
        if col not in df.columns:
            df[col] = 0
    
    df['dataset'] = 'UNSW-NB15'
    print(f"  Loaded: {len(df):,} rows, {df['label'].sum():,} attacks ({df['label'].sum()/len(df)*100:.1f}%)")
    
    return df

def load_bot_iot(folder_path: str, sample_size: int = None) -> pd.DataFrame:
    """Load and preprocess Bot-IoT dataset from multiple CSV files."""
    print(f"Loading Bot-IoT from: {folder_path}")
    
    csv_files = sorted(glob.glob(os.path.join(folder_path, "data_*.csv")))
    print(f"  Found {len(csv_files)} CSV files")
    
    # Use minimum 60 files
    files_to_use = min(60, len(csv_files))
    print(f"  Using {files_to_use} files")
    
    dfs = []
    total_rows = 0
    
    for i, file in enumerate(csv_files[:files_to_use], 1):
        try:
            df_chunk = pd.read_csv(file, low_memory=False)
            total_rows += len(df_chunk)
            
            # Convert attack column to binary label (0=benign, 1=attack)
            if 'attack' in df_chunk.columns:
                df_chunk['label'] = (df_chunk['attack'] == 1).astype(int)
            elif 'category' in df_chunk.columns:
                # Some Bot-IoT versions use 'category'
                df_chunk['label'] = (df_chunk['category'].str.lower() != 'normal').astype(int)
            
            # Compute missing features
            if 'dur' in df_chunk.columns and df_chunk['dur'].notna().any():
                if 'sbytes' in df_chunk.columns:
                    if 'sload' not in df_chunk.columns:
                        df_chunk['sload'] = df_chunk['sbytes'] / (df_chunk['dur'] + 0.001)
                    if 'smean' not in df_chunk.columns and 'spkts' in df_chunk.columns:
                        df_chunk['smean'] = df_chunk['sbytes'] / (df_chunk['spkts'] + 1)
                if 'dbytes' in df_chunk.columns:
                    if 'dload' not in df_chunk.columns:
                        df_chunk['dload'] = df_chunk['dbytes'] / (df_chunk['dur'] + 0.001)
                    if 'dmean' not in df_chunk.columns and 'dpkts' in df_chunk.columns:
                        df_chunk['dmean'] = df_chunk['dbytes'] / (df_chunk['dpkts'] + 1)
            
            # Bot-IoT has srate, drate, mean, stddev, min, max directly - keep them
            # Add TTL with default values (Bot-IoT doesn't have TTL)
            if 'sttl' not in df_chunk.columns:
                df_chunk['sttl'] = 64  # Common default TTL
            if 'dttl' not in df_chunk.columns:
                df_chunk['dttl'] = 64
            
            # Add missing UNSW-specific features with defaults
            for col in ['sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 
                       'swin', 'dwin', 'trans_depth', 'tcprtt', 'synack', 'ackdat']:
                if col not in df_chunk.columns:
                    df_chunk[col] = 0
            
            # Add any missing features before selecting
            for col in COMMON_FEATURES:
                if col not in df_chunk.columns:
                    df_chunk[col] = 0
                    
            df_chunk = df_chunk[COMMON_FEATURES + ['label']].copy()
            
            dfs.append(df_chunk)
            
            if i % 10 == 0:
                print(f"    Processed {i}/{files_to_use} files ({total_rows:,} rows)")
                
        except Exception as e:
            print(f"    Error reading {file}: {e}")
            continue
    
    if not dfs:
        raise ValueError("No Bot-IoT data loaded successfully")
    
    df = pd.concat(dfs, ignore_index=True)
    
    # Sample if too large
    if sample_size and len(df) > sample_size:
        df = df.groupby('label', group_keys=False).apply(
            lambda x: x.sample(min(len(x), sample_size // 2), random_state=42)
        ).reset_index(drop=True)
    
    df['dataset'] = 'Bot-IoT'
    print(f"  Loaded: {len(df):,} rows, {df['label'].sum():,} attacks ({df['label'].sum()/len(df)*100:.1f}%)")
    
    return df

def prepare_combined_dataset(unsw_path: str, bot_iot_path: str, 
                             unsw_sample: int = 100000, 
                             bot_sample: int = 100000) -> tuple:
    """Load and combine both datasets."""
    print("\n" + "="*80)
    print("LOADING DATASETS")
    print("="*80)
    
    # Load datasets
    df_unsw = load_unsw_nb15(unsw_path, sample_size=unsw_sample)
    df_bot = load_bot_iot(bot_iot_path, sample_size=bot_sample)
    
    # Combine
    df = pd.concat([df_unsw, df_bot], ignore_index=True)
    
    print(f"\nCombined dataset: {len(df):,} rows")
    print(f"  UNSW-NB15: {len(df_unsw):,} ({len(df_unsw)/len(df)*100:.1f}%)")
    print(f"  Bot-IoT:   {len(df_bot):,} ({len(df_bot)/len(df)*100:.1f}%)")
    print(f"  Total attacks: {df['label'].sum():,} ({df['label'].sum()/len(df)*100:.1f}%)")
    
    # Prepare features
    X = df[COMMON_FEATURES].copy()
    y = df['label'].astype(int)
    
    # Handle infinite and missing values
    X = X.replace([np.inf, -np.inf], np.nan)
    
    return X, y

def train_model(X_train, X_test, y_train, y_test):
    """Train Gradient Boosting model with preprocessing pipeline."""
    print("\n" + "="*80)
    print("TRAINING MODEL")
    print("="*80)
    
    # Create preprocessing + model pipeline
    pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler()),
        ('classifier', GradientBoostingClassifier(
            n_estimators=300,
            learning_rate=0.1,
            max_depth=6,
            min_samples_split=50,
            min_samples_leaf=20,
            subsample=0.8,
            random_state=42,
            verbose=1
        ))
    ])
    
    print(f"Training on {len(X_train):,} samples...")
    print(f"Features: {list(X_train.columns)}")
    
    pipeline.fit(X_train, y_train)
    
    print("\n" + "="*80)
    print("EVALUATION")
    print("="*80)
    
    # Training metrics
    y_train_pred = pipeline.predict(X_train)
    train_acc = accuracy_score(y_train, y_train_pred)
    print(f"Training Accuracy: {train_acc:.4f}")
    
    # Test predictions
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    
    # Metrics
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1_score': f1_score(y_test, y_pred),
        'roc_auc': roc_auc_score(y_test, y_proba),
        'train_accuracy': train_acc
    }
    
    print(f"\nTest Set Performance:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1-Score:  {metrics['f1_score']:.4f}")
    print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
    
    print(f"\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]:,}  FP={cm[0,1]:,}")
    print(f"  FN={cm[1,0]:,}  TP={cm[1,1]:,}")
    
    return pipeline, metrics

def main():
    """Main training workflow."""
    print("\n" + "="*80)
    print("COMBINED NETWORK ATTACK DETECTION MODEL TRAINING")
    print("="*80)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Paths
    unsw_path = 'UNSW_NB15_training-set.csv'
    bot_iot_path = 'Bot_IoT'
    model_dir = Path('trained_models')
    model_dir.mkdir(exist_ok=True)
    
    # Load and combine datasets
    X, y = prepare_combined_dataset(
        unsw_path, 
        bot_iot_path,
        unsw_sample=150000,  # Sample 150k from UNSW
        bot_sample=200000    # Sample 200k from Bot-IoT
    )
    
    # Train/test split
    print("\nSplitting data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  Training: {len(X_train):,} samples")
    print(f"  Testing:  {len(X_test):,} samples")
    
    # Train model
    model, metrics = train_model(X_train, X_test, y_train, y_test)
    
    # Save model
    model_path = model_dir / 'unsw_attack_detector.joblib'
    print(f"\n" + "="*80)
    print("SAVING MODEL")
    print("="*80)
    print(f"Saving to: {model_path}")
    joblib.dump(model, model_path)
    
    # Save training report
    report = {
        'model_type': 'Gradient Boosting Classifier',
        'datasets': ['UNSW-NB15', 'Bot-IoT'],
        'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'features': list(X.columns),
        'n_features': len(X.columns),
        'training_samples': len(X_train),
        'testing_samples': len(X_test),
        'metrics': metrics,
        'model_path': str(model_path)
    }
    
    report_path = model_dir / 'unsw_training_report.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Report saved to: {report_path}")
    print("\n" + "="*80)
    print("TRAINING COMPLETE!")
    print("="*80)
    print(f"Model ready for live detection with {metrics['accuracy']*100:.2f}% accuracy")

if __name__ == "__main__":
    main()
