"""
Model Evaluator Module for ML Phishing URL Detection System
Comprehensive model evaluation with multiple metrics
"""

import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    roc_curve, precision_recall_curve, average_precision_score
)
from sklearn.model_selection import cross_val_score
import logging
import time
from typing import Dict, Tuple
import joblib

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelEvaluator:
    """
    Comprehensive model evaluator for phishing URL detection
    Calculates and reports various performance metrics
    """

    def __init__(self):
        """Initialize model evaluator"""
        self.evaluation_results = {}

    def evaluate_model(self, model, X_test, y_test, model_name: str) -> Dict:
        """
        Evaluate a single model on test data

        Args:
            model: Trained model
            X_test: Test features
            y_test: Test labels
            model_name: Name of the model

        Returns:
            Dictionary of evaluation metrics
        """
        logger.info(f"Evaluating {model_name}...")

        # Make predictions
        start_time = time.time()
        y_pred = model.predict(X_test)
        prediction_time = time.time() - start_time

        # Get probability predictions if available
        try:
            y_pred_proba = model.predict_proba(X_test)[:, 1]
        except:
            y_pred_proba = y_pred

        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba) if len(np.unique(y_pred_proba)) > 1 else 0.0,
            'confusion_matrix': confusion_matrix(y_test, y_pred),
            'classification_report': classification_report(y_test, y_pred, output_dict=True),
            'prediction_time': prediction_time,
            'urls_per_second': len(X_test) / prediction_time if prediction_time > 0 else 0
        }

        # ROC curve data
        if len(np.unique(y_pred_proba)) > 1:
            fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            metrics['roc_curve'] = {'fpr': fpr, 'tpr': tpr}

        # Precision-Recall curve
        if len(np.unique(y_pred_proba)) > 1:
            precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
            metrics['pr_curve'] = {'precision': precision, 'recall': recall}
            metrics['avg_precision'] = average_precision_score(y_test, y_pred_proba)

        # Store predictions
        metrics['y_pred'] = y_pred
        metrics['y_pred_proba'] = y_pred_proba

        # Log metrics
        logger.info(f"{model_name} - Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"{model_name} - Precision: {metrics['precision']:.4f}")
        logger.info(f"{model_name} - Recall: {metrics['recall']:.4f}")
        logger.info(f"{model_name} - F1-Score: {metrics['f1_score']:.4f}")
        logger.info(f"{model_name} - ROC-AUC: {metrics['roc_auc']:.4f}")
        logger.info(f"{model_name} - Prediction Speed: {metrics['urls_per_second']:.0f} URLs/sec")

        return metrics

    def evaluate_all_models(self, models: Dict, X_test, y_test) -> Dict:
        """
        Evaluate all models

        Args:
            models: Dictionary of trained models
            X_test: Test features
            y_test: Test labels

        Returns:
            Dictionary of evaluation results for all models
        """
        logger.info("=" * 80)
        logger.info("EVALUATING ALL MODELS")
        logger.info("=" * 80)

        results = {}

        for name, model in models.items():
            try:
                results[name] = self.evaluate_model(model, X_test, y_test, name)
            except Exception as e:
                logger.error(f"Error evaluating {name}: {e}")

        logger.info("=" * 80)
        logger.info("MODEL EVALUATION COMPLETE")
        logger.info("=" * 80)

        self.evaluation_results = results
        return results

    def cross_validate_models(self, models: Dict, X_train, y_train, cv: int = 5) -> Dict:
        """
        Perform cross-validation on all models

        Args:
            models: Dictionary of trained models
            X_train: Training features
            y_train: Training labels
            cv: Number of cross-validation folds

        Returns:
            Dictionary of cross-validation scores
        """
        logger.info(f"Performing {cv}-fold cross-validation...")

        cv_results = {}

        for name, model in models.items():
            try:
                logger.info(f"Cross-validating {name}...")
                scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
                cv_results[name] = {
                    'scores': scores,
                    'mean': scores.mean(),
                    'std': scores.std()
                }
                logger.info(f"{name} - CV Accuracy: {scores.mean():.4f} (+/- {scores.std():.4f})")
            except Exception as e:
                logger.error(f"Error cross-validating {name}: {e}")

        return cv_results

    def get_feature_importance(self, model, feature_names, model_name: str) -> pd.DataFrame:
        """
        Extract feature importance from a model

        Args:
            model: Trained model
            feature_names: List of feature names
            model_name: Name of the model

        Returns:
            DataFrame with feature importance scores
        """
        try:
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            elif hasattr(model, 'coef_'):
                importances = np.abs(model.coef_[0])
            else:
                logger.warning(f"{model_name} does not have feature importance")
                return None

            importance_df = pd.DataFrame({
                'feature': feature_names,
                'importance': importances
            }).sort_values('importance', ascending=False)

            return importance_df

        except Exception as e:
            logger.error(f"Error extracting feature importance from {model_name}: {e}")
            return None

    def generate_comparison_table(self, results: Dict) -> pd.DataFrame:
        """
        Generate comparison table of all models

        Args:
            results: Dictionary of evaluation results

        Returns:
            DataFrame with model comparison
        """
        comparison_data = []

        for name, metrics in results.items():
            comparison_data.append({
                'Model': name.replace('_', ' ').title(),
                'Accuracy': metrics['accuracy'],
                'Precision': metrics['precision'],
                'Recall': metrics['recall'],
                'F1-Score': metrics['f1_score'],
                'ROC-AUC': metrics['roc_auc'],
                'Speed (URLs/sec)': metrics['urls_per_second']
            })

        df = pd.DataFrame(comparison_data)
        df = df.sort_values('Accuracy', ascending=False)

        return df

    def print_detailed_report(self, results: Dict):
        """
        Print detailed evaluation report

        Args:
            results: Dictionary of evaluation results
        """
        print("\n" + "=" * 80)
        print("DETAILED MODEL EVALUATION REPORT")
        print("=" * 80)

        for name, metrics in results.items():
            print(f"\n{name.upper().replace('_', ' ')}")
            print("-" * 80)
            print(f"Accuracy:  {metrics['accuracy']:.4f}")
            print(f"Precision: {metrics['precision']:.4f}")
            print(f"Recall:    {metrics['recall']:.4f}")
            print(f"F1-Score:  {metrics['f1_score']:.4f}")
            print(f"ROC-AUC:   {metrics['roc_auc']:.4f}")
            print(f"Speed:     {metrics['urls_per_second']:.0f} URLs/sec")

            print("\nConfusion Matrix:")
            cm = metrics['confusion_matrix']
            print(f"  TN: {cm[0, 0]:6d}  |  FP: {cm[0, 1]:6d}")
            print(f"  FN: {cm[1, 0]:6d}  |  TP: {cm[1, 1]:6d}")

        print("\n" + "=" * 80)

    def get_false_predictions(self, y_test, y_pred, X_test, urls=None) -> Tuple:
        """
        Get false positive and false negative examples

        Args:
            y_test: True labels
            y_pred: Predicted labels
            X_test: Test features
            urls: List of URLs (optional)

        Returns:
            Tuple of (false_positives, false_negatives)
        """
        # False positives (predicted phishing, actually legitimate)
        fp_mask = (y_test == 0) & (y_pred == 1)
        fp_indices = np.where(fp_mask)[0]

        # False negatives (predicted legitimate, actually phishing)
        fn_mask = (y_test == 1) & (y_pred == 0)
        fn_indices = np.where(fn_mask)[0]

        fp_data = {
            'indices': fp_indices,
            'count': len(fp_indices)
        }

        fn_data = {
            'indices': fn_indices,
            'count': len(fn_indices)
        }

        if urls is not None:
            fp_data['urls'] = [urls[i] for i in fp_indices]
            fn_data['urls'] = [urls[i] for i in fn_indices]

        logger.info(f"False Positives: {len(fp_indices)}")
        logger.info(f"False Negatives: {len(fn_indices)}")

        return fp_data, fn_data

    def save_evaluation_results(self, results: Dict, filename: str = 'models/evaluation_results.pkl'):
        """
        Save evaluation results to disk

        Args:
            results: Dictionary of evaluation results
            filename: Output filename
        """
        logger.info(f"Saving evaluation results to {filename}")
        joblib.dump(results, filename)

    def load_evaluation_results(self, filename: str = 'models/evaluation_results.pkl') -> Dict:
        """
        Load evaluation results from disk

        Args:
            filename: Input filename

        Returns:
            Dictionary of evaluation results
        """
        logger.info(f"Loading evaluation results from {filename}")
        return joblib.load(filename)


if __name__ == '__main__':
    # Test model evaluator
    logger.info("Model evaluator module loaded successfully")
