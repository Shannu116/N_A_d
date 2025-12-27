#!/usr/bin/env python3
"""
UNSW-NB15 Attack Detection Model - Testing & Evaluation
======================================================

Tests the trained model on the UNSW_NB15_testing-set.csv and generates
comprehensive performance metrics and visualizations.

Usage:
    python3 test_model.py
    python3 test_model.py --model-path trained_models/unsw_attack_detector.joblib
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
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    average_precision_score
)

warnings.filterwarnings('ignore')

# Try to import matplotlib for visualizations (optional)
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    print("[INFO] matplotlib/seaborn not available. Skipping visualizations.")


# Configuration
TEST_DATASET_PATH = 'UNSW_NB15_testing-set.csv'
LABEL_COLUMN = 'label'
ATTACK_CAT_COLUMN = 'attack_cat'
ID_COLUMN = 'id'
DROP_COLUMNS = [ID_COLUMN, ATTACK_CAT_COLUMN]


def load_test_data(data_path: str) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load testing dataset.
    
    Returns:
        X_test, y_test
    """
    print(f"Loading test dataset from: {data_path}")
    
    if not os.path.exists(data_path):
        raise FileNotFoundError(
            f"Test dataset not found: {data_path}\n"
            f"Please ensure UNSW_NB15_testing-set.csv is in the current directory."
        )
    
    # Load data
    df = pd.read_csv(data_path)
    print(f"Test dataset shape: {df.shape}")
    print(f"Total test samples: {len(df):,}")
    
    # Check label column exists
    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"Label column '{LABEL_COLUMN}' not found in dataset")
    
    # Separate features and target
    y_test = df[LABEL_COLUMN].astype(int)
    X_test = df.drop(columns=[LABEL_COLUMN] + [c for c in DROP_COLUMNS if c in df.columns])
    
    # Print class distribution
    class_counts = y_test.value_counts().to_dict()
    print(f"\nClass distribution in test set:")
    print(f"  Benign (0): {class_counts.get(0, 0):,} ({class_counts.get(0, 0)/len(y_test)*100:.1f}%)")
    print(f"  Attack (1): {class_counts.get(1, 0):,} ({class_counts.get(1, 0)/len(y_test)*100:.1f}%)")
    
    # Handle infinite values
    X_test = X_test.replace([np.inf, -np.inf], np.nan)
    
    return X_test, y_test


def load_model(model_path: str):
    """Load the trained model."""
    print(f"\nLoading trained model from: {model_path}")
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found: {model_path}\n"
            f"Please run train_unsw_nb15.py first to train the model."
        )
    
    model = joblib.load(model_path)
    print("✓ Model loaded successfully")
    
    return model


def evaluate_model(
    model,
    X_test: pd.DataFrame,
    y_test: pd.Series
) -> Dict:
    """
    Evaluate model on test set with comprehensive metrics.
    
    Returns:
        Dictionary with all evaluation metrics
    """
    print(f"\n{'='*70}")
    print("EVALUATING MODEL ON TEST SET")
    print('='*70)
    
    # Make predictions
    print("Making predictions...")
    y_pred = model.predict(X_test)
    
    # Get prediction probabilities
    y_prob = None
    try:
        if hasattr(model, 'predict_proba'):
            y_prob = model.predict_proba(X_test)[:, 1]
            print("✓ Prediction probabilities obtained")
    except Exception as e:
        print(f"[WARN] Could not get prediction probabilities: {e}")
    
    # Calculate metrics
    print("\nCalculating metrics...")
    
    metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
    }
    
    # ROC-AUC if probabilities available
    if y_prob is not None and len(np.unique(y_test)) == 2:
        try:
            metrics['roc_auc'] = float(roc_auc_score(y_test, y_prob))
            metrics['average_precision'] = float(average_precision_score(y_test, y_prob))
        except Exception as e:
            print(f"[WARN] Could not calculate ROC-AUC: {e}")
            metrics['roc_auc'] = None
            metrics['average_precision'] = None
    else:
        metrics['roc_auc'] = None
        metrics['average_precision'] = None
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    metrics['confusion_matrix'] = {
        'true_negative': int(tn),
        'false_positive': int(fp),
        'false_negative': int(fn),
        'true_positive': int(tp)
    }
    
    # Additional metrics
    metrics['specificity'] = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    metrics['false_positive_rate'] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    metrics['false_negative_rate'] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    
    # Classification report
    metrics['classification_report'] = classification_report(
        y_test, y_pred, target_names=['Benign', 'Attack'], zero_division=0
    )
    
    # Store predictions for later analysis
    metrics['y_true'] = y_test.tolist()
    metrics['y_pred'] = y_pred.tolist()
    if y_prob is not None:
        metrics['y_prob'] = y_prob.tolist()
    
    return metrics


def print_results(metrics: Dict):
    """Print evaluation results in a formatted way."""
    print(f"\n{'='*70}")
    print("TEST SET PERFORMANCE RESULTS")
    print('='*70)
    
    print("\n📊 Classification Metrics:")
    print(f"  Accuracy:          {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"  Precision:         {metrics['precision']:.4f}")
    print(f"  Recall (TPR):      {metrics['recall']:.4f}")
    print(f"  F1 Score:          {metrics['f1_score']:.4f}")
    print(f"  Specificity (TNR): {metrics['specificity']:.4f}")
    
    if metrics['roc_auc'] is not None:
        print(f"  ROC-AUC:           {metrics['roc_auc']:.4f}")
        print(f"  Avg Precision:     {metrics['average_precision']:.4f}")
    
    print(f"\n🎯 Error Rates:")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.4f}")
    print(f"  False Negative Rate: {metrics['false_negative_rate']:.4f}")
    
    cm = metrics['confusion_matrix']
    print(f"\n📈 Confusion Matrix:")
    print(f"                 Predicted Benign | Predicted Attack")
    print(f"  Actual Benign:  {cm['true_negative']:>15,} | {cm['false_positive']:>15,}")
    print(f"  Actual Attack:  {cm['false_negative']:>15,} | {cm['true_positive']:>15,}")
    
    print(f"\n📝 Detailed Classification Report:")
    print(metrics['classification_report'])
    
    print('='*70)


def plot_confusion_matrix(metrics: Dict, output_dir: str = 'test_results'):
    """Generate confusion matrix visualization."""
    if not PLOTTING_AVAILABLE:
        return
    
    cm = metrics['confusion_matrix']
    cm_array = np.array([
        [cm['true_negative'], cm['false_positive']],
        [cm['false_negative'], cm['true_positive']]
    ])
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm_array,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=['Benign', 'Attack'],
        yticklabels=['Benign', 'Attack'],
        cbar_kws={'label': 'Count'}
    )
    plt.title('Confusion Matrix - Test Set', fontsize=14, fontweight='bold')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    
    os.makedirs(output_dir, exist_ok=True)
    save_path = os.path.join(output_dir, 'confusion_matrix.png')
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Confusion matrix saved to: {save_path}")


def plot_roc_curve(metrics: Dict, output_dir: str = 'test_results'):
    """Generate ROC curve visualization."""
    if not PLOTTING_AVAILABLE or metrics.get('y_prob') is None:
        return
    
    y_true = np.array(metrics['y_true'])
    y_prob = np.array(metrics['y_prob'])
    
    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    roc_auc = metrics['roc_auc']
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate (Recall)')
    plt.title('ROC Curve - Test Set', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right')
    plt.grid(alpha=0.3)
    plt.tight_layout()
    
    os.makedirs(output_dir, exist_ok=True)
    save_path = os.path.join(output_dir, 'roc_curve.png')
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ ROC curve saved to: {save_path}")


def plot_precision_recall_curve(metrics: Dict, output_dir: str = 'test_results'):
    """Generate Precision-Recall curve visualization."""
    if not PLOTTING_AVAILABLE or metrics.get('y_prob') is None:
        return
    
    y_true = np.array(metrics['y_true'])
    y_prob = np.array(metrics['y_prob'])
    
    precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
    avg_precision = metrics['average_precision']
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color='blue', lw=2, label=f'PR curve (AP = {avg_precision:.4f})')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve - Test Set', fontsize=14, fontweight='bold')
    plt.legend(loc='lower left')
    plt.grid(alpha=0.3)
    plt.tight_layout()
    
    os.makedirs(output_dir, exist_ok=True)
    save_path = os.path.join(output_dir, 'precision_recall_curve.png')
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Precision-Recall curve saved to: {save_path}")


def save_test_report(metrics: Dict, output_dir: str = 'test_results'):
    """Save test results to JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    
    # Create a clean copy without large arrays
    report = metrics.copy()
    report.pop('y_true', None)
    report.pop('y_pred', None)
    report.pop('y_prob', None)
    
    report['timestamp'] = datetime.now().isoformat()
    report['test_dataset'] = TEST_DATASET_PATH
    
    report_path = os.path.join(output_dir, 'test_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"✓ Test report saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Test UNSW-NB15 attack detection model on test set'
    )
    parser.add_argument(
        '--model-path',
        default='trained_models/unsw_attack_detector.joblib',
        help='Path to trained model file'
    )
    parser.add_argument(
        '--test-data',
        default=TEST_DATASET_PATH,
        help=f'Path to test dataset CSV (default: {TEST_DATASET_PATH})'
    )
    parser.add_argument(
        '--output-dir',
        default='test_results',
        help='Output directory for results and visualizations (default: test_results)'
    )
    parser.add_argument(
        '--no-plots',
        action='store_true',
        help='Skip generating visualizations'
    )
    args = parser.parse_args()
    
    print("="*70)
    print("UNSW-NB15 Attack Detection Model - Testing & Evaluation")
    print("="*70)
    
    try:
        # Load test data
        X_test, y_test = load_test_data(args.test_data)
        
        # Load model
        model = load_model(args.model_path)
        
        # Evaluate model
        metrics = evaluate_model(model, X_test, y_test)
        
        # Print results
        print_results(metrics)
        
        # Generate visualizations
        if not args.no_plots and PLOTTING_AVAILABLE:
            print(f"\n{'='*70}")
            print("GENERATING VISUALIZATIONS")
            print('='*70)
            plot_confusion_matrix(metrics, args.output_dir)
            plot_roc_curve(metrics, args.output_dir)
            plot_precision_recall_curve(metrics, args.output_dir)
        
        # Save report
        print(f"\n{'='*70}")
        print("SAVING RESULTS")
        print('='*70)
        save_test_report(metrics, args.output_dir)
        
        print(f"\n{'='*70}")
        print("✓ TESTING COMPLETE")
        print('='*70)
        print(f"\nSummary:")
        print(f"  Test Accuracy: {metrics['accuracy']*100:.2f}%")
        print(f"  F1 Score:      {metrics['f1_score']:.4f}")
        if metrics['roc_auc']:
            print(f"  ROC-AUC:       {metrics['roc_auc']:.4f}")
        print(f"\nResults saved to: {args.output_dir}/")
        print('='*70)
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
