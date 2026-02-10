"""
Visualizer Module for ML Phishing URL Detection System
Comprehensive visualization generation using Matplotlib and Seaborn
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc
import logging
import os
import yaml

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Visualizer:
    """
    Comprehensive visualizer for phishing URL detection results
    Generates and saves publication-quality plots
    """

    def __init__(self, config_path: str = 'config.yaml'):
        """Initialize visualizer with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.figsize = tuple(self.config['visualization']['figsize'])
        self.dpi = self.config['visualization']['dpi']

        # Set style
        try:
            sns.set_style('darkgrid')
            sns.set_palette(self.config['visualization']['color_palette'])
        except:
            sns.set_style('darkgrid')

        # Create output directories
        os.makedirs('visualizations/confusion_matrices', exist_ok=True)
        os.makedirs('visualizations/roc_curves', exist_ok=True)
        os.makedirs('visualizations/feature_importance', exist_ok=True)
        os.makedirs('visualizations/performance_metrics', exist_ok=True)

    def plot_label_distribution(self, df: pd.DataFrame, save_path: str = 'visualizations/label_distribution.png'):
        """Plot distribution of phishing vs legitimate URLs"""
        logger.info("Plotting label distribution...")

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # Pie chart
        labels_count = df['Label'].value_counts()
        colors = ['#2ecc71', '#e74c3c']
        explode = (0.05, 0.05)

        ax1.pie(labels_count.values, labels=['Legitimate', 'Phishing'],
                autopct='%1.1f%%', startangle=90, colors=colors, explode=explode,
                shadow=True, textprops={'fontsize': 12, 'weight': 'bold'})
        ax1.set_title('URL Distribution', fontsize=14, weight='bold')

        # Bar chart
        ax2.bar(['Legitimate', 'Phishing'], labels_count.values, color=colors, edgecolor='black')
        ax2.set_ylabel('Count', fontsize=12, weight='bold')
        ax2.set_title('URL Count by Type', fontsize=14, weight='bold')
        ax2.grid(axis='y', alpha=0.3)

        for i, v in enumerate(labels_count.values):
            ax2.text(i, v + labels_count.max() * 0.01, str(v), ha='center',
                    va='bottom', fontsize=11, weight='bold')

        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved label distribution plot to {save_path}")

    def plot_feature_correlation(self, df: pd.DataFrame, save_path: str = 'visualizations/feature_correlation.png'):
        """Plot feature correlation heatmap"""
        logger.info("Plotting feature correlation heatmap...")

        # Select numeric features only
        exclude_cols = ['url', 'Label', 'dataset_source', 'url_normalized']
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        numeric_cols = [col for col in numeric_cols if col not in exclude_cols]

        # Limit to top 20 features for readability
        if len(numeric_cols) > 20:
            # Calculate correlation with label
            correlations = df[numeric_cols].corrwith(df['Label']).abs()
            top_features = correlations.nlargest(20).index.tolist()
            numeric_cols = top_features

        correlation_matrix = df[numeric_cols].corr()

        plt.figure(figsize=(16, 14))
        sns.heatmap(correlation_matrix, annot=False, cmap='coolwarm', center=0,
                   square=True, linewidths=0.5, cbar_kws={"shrink": 0.8})
        plt.title('Feature Correlation Heatmap (Top 20 Features)', fontsize=16, weight='bold', pad=20)
        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved feature correlation heatmap to {save_path}")

    def plot_feature_distributions(self, df: pd.DataFrame, save_path: str = 'visualizations/feature_distributions.png'):
        """Plot distributions of top features"""
        logger.info("Plotting feature distributions...")

        # Select numeric features
        exclude_cols = ['url', 'Label', 'dataset_source', 'url_normalized']
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        numeric_cols = [col for col in numeric_cols if col not in exclude_cols]

        # Get top 10 features by correlation with label
        if 'Label' in df.columns and len(numeric_cols) > 0:
            correlations = df[numeric_cols].corrwith(df['Label']).abs()
            top_features = correlations.nlargest(10).index.tolist()
        else:
            top_features = numeric_cols[:10]

        fig, axes = plt.subplots(5, 2, figsize=(16, 20))
        axes = axes.ravel()

        for idx, feature in enumerate(top_features):
            if idx < len(axes):
                try:
                    # Plot distribution for each class
                    for label in [0, 1]:
                        data = df[df['Label'] == label][feature]
                        axes[idx].hist(data, bins=30, alpha=0.6,
                                     label='Legitimate' if label == 0 else 'Phishing')

                    axes[idx].set_title(f'{feature}', fontsize=11, weight='bold')
                    axes[idx].set_xlabel('Value', fontsize=9)
                    axes[idx].set_ylabel('Frequency', fontsize=9)
                    axes[idx].legend()
                    axes[idx].grid(alpha=0.3)
                except Exception as e:
                    logger.warning(f"Error plotting {feature}: {e}")

        plt.suptitle('Top 10 Feature Distributions', fontsize=16, weight='bold', y=0.995)
        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved feature distributions plot to {save_path}")

    def plot_confusion_matrices(self, results: dict):
        """Plot confusion matrices for all models"""
        logger.info("Plotting confusion matrices...")

        for model_name, metrics in results.items():
            if 'confusion_matrix' in metrics:
                cm = metrics['confusion_matrix']

                plt.figure(figsize=(8, 6))
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
                          xticklabels=['Legitimate', 'Phishing'],
                          yticklabels=['Legitimate', 'Phishing'])

                plt.title(f'Confusion Matrix - {model_name.replace("_", " ").title()}',
                        fontsize=14, weight='bold')
                plt.ylabel('True Label', fontsize=12, weight='bold')
                plt.xlabel('Predicted Label', fontsize=12, weight='bold')

                # Add accuracy text
                accuracy = metrics.get('accuracy', 0)
                plt.text(1, 2.5, f'Accuracy: {accuracy:.4f}',
                        fontsize=11, ha='center', weight='bold')

                save_path = f'visualizations/confusion_matrices/{model_name}_confusion_matrix.png'
                plt.tight_layout()
                plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
                plt.close()

                logger.info(f"Saved confusion matrix for {model_name}")

    def plot_roc_curves(self, results: dict, save_path: str = 'visualizations/roc_curves/all_models_roc.png'):
        """Plot ROC curves for all models on one plot"""
        logger.info("Plotting ROC curves...")

        plt.figure(figsize=self.figsize)

        colors = plt.cm.Set3(np.linspace(0, 1, len(results)))

        for idx, (model_name, metrics) in enumerate(results.items()):
            if 'roc_curve' in metrics:
                fpr = metrics['roc_curve']['fpr']
                tpr = metrics['roc_curve']['tpr']
                roc_auc = metrics['roc_auc']

                plt.plot(fpr, tpr, color=colors[idx], lw=2,
                        label=f'{model_name.replace("_", " ").title()} (AUC = {roc_auc:.3f})')

        plt.plot([0, 1], [0, 1], 'k--', lw=2, label='Random Classifier')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate', fontsize=12, weight='bold')
        plt.ylabel('True Positive Rate', fontsize=12, weight='bold')
        plt.title('ROC Curves - All Models', fontsize=14, weight='bold')
        plt.legend(loc="lower right", fontsize=10)
        plt.grid(alpha=0.3)

        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved ROC curves to {save_path}")

    def plot_precision_recall_curves(self, results: dict,
                                     save_path: str = 'visualizations/roc_curves/all_models_pr.png'):
        """Plot Precision-Recall curves for all models"""
        logger.info("Plotting Precision-Recall curves...")

        plt.figure(figsize=self.figsize)

        colors = plt.cm.Set3(np.linspace(0, 1, len(results)))

        for idx, (model_name, metrics) in enumerate(results.items()):
            if 'pr_curve' in metrics:
                precision = metrics['pr_curve']['precision']
                recall = metrics['pr_curve']['recall']
                avg_precision = metrics.get('avg_precision', 0)

                plt.plot(recall, precision, color=colors[idx], lw=2,
                        label=f'{model_name.replace("_", " ").title()} (AP = {avg_precision:.3f})')

        plt.xlabel('Recall', fontsize=12, weight='bold')
        plt.ylabel('Precision', fontsize=12, weight='bold')
        plt.title('Precision-Recall Curves - All Models', fontsize=14, weight='bold')
        plt.legend(loc="best", fontsize=10)
        plt.grid(alpha=0.3)
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])

        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved Precision-Recall curves to {save_path}")

    def plot_model_comparison(self, results: dict,
                             save_path: str = 'visualizations/performance_metrics/model_comparison.png'):
        """Plot model performance comparison"""
        logger.info("Plotting model comparison...")

        # Prepare data
        models = []
        accuracies = []
        precisions = []
        recalls = []
        f1_scores = []

        for model_name, metrics in results.items():
            models.append(model_name.replace('_', ' ').title())
            accuracies.append(metrics.get('accuracy', 0))
            precisions.append(metrics.get('precision', 0))
            recalls.append(metrics.get('recall', 0))
            f1_scores.append(metrics.get('f1_score', 0))

        # Create grouped bar chart
        x = np.arange(len(models))
        width = 0.2

        fig, ax = plt.subplots(figsize=(16, 8))

        bars1 = ax.bar(x - 1.5*width, accuracies, width, label='Accuracy', color='#3498db')
        bars2 = ax.bar(x - 0.5*width, precisions, width, label='Precision', color='#2ecc71')
        bars3 = ax.bar(x + 0.5*width, recalls, width, label='Recall', color='#f39c12')
        bars4 = ax.bar(x + 1.5*width, f1_scores, width, label='F1-Score', color='#e74c3c')

        ax.set_xlabel('Models', fontsize=12, weight='bold')
        ax.set_ylabel('Score', fontsize=12, weight='bold')
        ax.set_title('Model Performance Comparison', fontsize=14, weight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(models, rotation=45, ha='right')
        ax.legend(fontsize=11)
        ax.grid(axis='y', alpha=0.3)
        ax.set_ylim([0, 1.1])

        # Add value labels on bars
        def add_labels(bars):
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.3f}', ha='center', va='bottom', fontsize=8)

        add_labels(bars1)
        add_labels(bars2)
        add_labels(bars3)
        add_labels(bars4)

        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved model comparison to {save_path}")

    def plot_accuracy_comparison(self, results: dict,
                                save_path: str = 'visualizations/performance_metrics/accuracy_comparison.png'):
        """Plot horizontal bar chart of model accuracies"""
        logger.info("Plotting accuracy comparison...")

        models = []
        accuracies = []

        for model_name, metrics in results.items():
            models.append(model_name.replace('_', ' ').title())
            accuracies.append(metrics.get('accuracy', 0))

        # Sort by accuracy
        sorted_indices = np.argsort(accuracies)
        models = [models[i] for i in sorted_indices]
        accuracies = [accuracies[i] for i in sorted_indices]

        plt.figure(figsize=(10, 8))
        colors = plt.cm.RdYlGn(np.array(accuracies))

        bars = plt.barh(models, accuracies, color=colors, edgecolor='black')
        plt.xlabel('Accuracy', fontsize=12, weight='bold')
        plt.title('Model Accuracy Comparison', fontsize=14, weight='bold')
        plt.xlim([0, 1.0])
        plt.grid(axis='x', alpha=0.3)

        # Add value labels
        for i, (model, acc) in enumerate(zip(models, accuracies)):
            plt.text(acc + 0.01, i, f'{acc:.4f}', va='center', fontsize=10, weight='bold')

        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved accuracy comparison to {save_path}")

    def plot_feature_importance(self, importance_df: pd.DataFrame, model_name: str, top_n: int = 20):
        """Plot feature importance"""
        logger.info(f"Plotting feature importance for {model_name}...")

        if importance_df is None or len(importance_df) == 0:
            logger.warning(f"No feature importance data for {model_name}")
            return

        # Get top N features
        top_features = importance_df.head(top_n)

        plt.figure(figsize=(12, 10))
        colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(top_features)))

        plt.barh(range(len(top_features)), top_features['importance'].values, color=colors, edgecolor='black')
        plt.yticks(range(len(top_features)), top_features['feature'].values)
        plt.xlabel('Importance Score', fontsize=12, weight='bold')
        plt.title(f'Top {top_n} Feature Importance - {model_name.replace("_", " ").title()}',
                 fontsize=14, weight='bold')
        plt.gca().invert_yaxis()
        plt.grid(axis='x', alpha=0.3)

        save_path = f'visualizations/feature_importance/{model_name}_feature_importance.png'
        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved feature importance plot to {save_path}")

    def plot_training_times(self, training_times: dict,
                           save_path: str = 'visualizations/performance_metrics/training_times.png'):
        """Plot training time comparison"""
        logger.info("Plotting training times...")

        models = [name.replace('_', ' ').title() for name in training_times.keys()]
        times = list(training_times.values())

        plt.figure(figsize=(12, 6))
        colors = plt.cm.Spectral(np.linspace(0, 1, len(models)))

        bars = plt.bar(models, times, color=colors, edgecolor='black')
        plt.ylabel('Training Time (seconds)', fontsize=12, weight='bold')
        plt.title('Model Training Time Comparison', fontsize=14, weight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.grid(axis='y', alpha=0.3)

        # Add value labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2f}s', ha='center', va='bottom', fontsize=10, weight='bold')

        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved training times plot to {save_path}")

    def plot_prediction_speed(self, results: dict,
                             save_path: str = 'visualizations/performance_metrics/prediction_speed.png'):
        """Plot prediction speed comparison"""
        logger.info("Plotting prediction speed...")

        models = []
        speeds = []

        for model_name, metrics in results.items():
            models.append(model_name.replace('_', ' ').title())
            speeds.append(metrics.get('urls_per_second', 0))

        plt.figure(figsize=(12, 6))
        colors = plt.cm.Paired(np.linspace(0, 1, len(models)))

        bars = plt.bar(models, speeds, color=colors, edgecolor='black')
        plt.ylabel('URLs per Second', fontsize=12, weight='bold')
        plt.title('Model Prediction Speed Comparison', fontsize=14, weight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.grid(axis='y', alpha=0.3)

        # Add value labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.0f}', ha='center', va='bottom', fontsize=10, weight='bold')

        plt.tight_layout()
        plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
        plt.close()

        logger.info(f"Saved prediction speed plot to {save_path}")

    def generate_all_visualizations(self, df: pd.DataFrame, results: dict,
                                   training_times: dict, feature_importances: dict):
        """Generate all visualizations"""
        logger.info("=" * 80)
        logger.info("GENERATING ALL VISUALIZATIONS")
        logger.info("=" * 80)

        # Dataset visualizations
        self.plot_label_distribution(df)
        self.plot_feature_correlation(df)
        self.plot_feature_distributions(df)

        # Model performance visualizations
        self.plot_confusion_matrices(results)
        self.plot_roc_curves(results)
        self.plot_precision_recall_curves(results)
        self.plot_model_comparison(results)
        self.plot_accuracy_comparison(results)

        # Feature importance
        for model_name, importance_df in feature_importances.items():
            self.plot_feature_importance(importance_df, model_name)

        # Training metrics
        self.plot_training_times(training_times)
        self.plot_prediction_speed(results)

        logger.info("=" * 80)
        logger.info("ALL VISUALIZATIONS GENERATED SUCCESSFULLY")
        logger.info("=" * 80)


if __name__ == '__main__':
    logger.info("Visualizer module loaded successfully")
