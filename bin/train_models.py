"""
Standalone script to train all models
Can be run independently of the main CLI
"""

import sys
import os

# Add src to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(parent_dir, 'src'))
# Change to parent directory so models save in correct location
os.chdir(parent_dir)

from data_loader import DataLoader
from feature_extractor import FeatureExtractor
from model_trainer import ModelTrainer
from model_evaluator import ModelEvaluator
from visualizer import Visualizer
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/training.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def main():
    """Main training pipeline"""
    logger.info("=" * 80)
    logger.info("ML PHISHING URL DETECTOR - MODEL TRAINING PIPELINE")
    logger.info("=" * 80)

    try:
        # Step 1: Load and merge datasets
        logger.info("\n[STEP 1/6] Loading and merging datasets...")
        loader = DataLoader()
        df = loader.load_and_merge_all(include_supplementary=False)

        logger.info(f"\nDataset loaded successfully!")
        logger.info(f"Total URLs: {len(df)}")

        # SPEED OPTIMIZATION: Use smaller sample for faster training
        # Comment out these lines to use full dataset
        SAMPLE_SIZE = 50000  # Use 50k URLs instead of 200k+ for 4x faster training
        if len(df) > SAMPLE_SIZE:
            logger.info(f"🚀 FAST MODE: Sampling {SAMPLE_SIZE} URLs for quick training (2-5 mins)")
            df = df.sample(n=SAMPLE_SIZE, random_state=42).reset_index(drop=True)

        logger.info(f"Training with {len(df)} URLs")
        logger.info(f"Legitimate: {len(df[df['Label'] == 0])}")
        logger.info(f"Phishing: {len(df[df['Label'] == 1])}")

        # Step 2: Extract features
        logger.info("\n[STEP 2/6] Extracting features from URLs...")
        extractor = FeatureExtractor()
        df = extractor.extract_features_from_dataframe(df)

        logger.info(f"Feature extraction complete!")
        logger.info(f"Total features: {len(extractor.get_feature_names())}")

        # Step 3: Prepare data
        logger.info("\n[STEP 3/6] Preparing training and test datasets...")
        trainer = ModelTrainer()
        X_train, X_test, y_train, y_test, feature_names = trainer.prepare_data(df)

        logger.info(f"Data preparation complete!")
        logger.info(f"Training samples: {len(X_train)}")
        logger.info(f"Test samples: {len(X_test)}")

        # Step 4: Train models
        logger.info("\n[STEP 4/6] Training ML models...")
        logger.info("⚡ ULTRA-FAST MODE: 50k samples, no GridSearch, 2 models only")
        logger.info("Expected time: 2-5 minutes")
        logger.info("(For full dataset & all models, edit train_models.py)")

        models = trainer.train_all_models(X_train, X_test, y_train, y_test, fast_mode=True)

        logger.info(f"\nModel training complete!")
        logger.info(f"Models trained: {len(models)}")

        # Save models
        trainer.save_models(models, feature_names)

        # Step 5: Evaluate models
        logger.info("\n[STEP 5/6] Evaluating model performance...")
        evaluator = ModelEvaluator()
        results = evaluator.evaluate_all_models(models, X_test, y_test)

        # Save evaluation results
        evaluator.save_evaluation_results(results)

        # Print detailed report
        evaluator.print_detailed_report(results)

        # Generate comparison table
        comparison_df = evaluator.generate_comparison_table(results)
        logger.info("\nModel Comparison Table:")
        logger.info("\n" + comparison_df.to_string(index=False))

        # Step 6: Generate visualizations
        logger.info("\n[STEP 6/6] Generating visualizations...")

        visualizer = Visualizer()

        # Get feature importance for tree-based models
        feature_importances = {}
        for name, model in models.items():
            importance_df = evaluator.get_feature_importance(model, feature_names, name)
            if importance_df is not None:
                feature_importances[name] = importance_df

        # Generate all visualizations
        visualizer.generate_all_visualizations(
            df, results, trainer.training_times, feature_importances
        )

        logger.info("\n" + "=" * 80)
        logger.info("TRAINING PIPELINE COMPLETED SUCCESSFULLY!")
        logger.info("=" * 80)

        logger.info("\nNext steps:")
        logger.info("1. Run 'python main.py' to use the interactive CLI")
        logger.info("2. Check 'visualizations/' folder for performance plots")
        logger.info("3. Review 'models/' folder for saved models")

        return 0

    except Exception as e:
        logger.error(f"\nError during training: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    # Create logs directory
    os.makedirs('logs', exist_ok=True)

    exit_code = main()
    sys.exit(exit_code)
