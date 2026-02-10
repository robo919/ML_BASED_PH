"""
Model Trainer Module for ML Phishing URL Detection System
Trains multiple ML models with hyperparameter tuning
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import joblib
import yaml
import logging
import time
from typing import Dict, Tuple, List
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Comprehensive model trainer for phishing URL detection
    Trains and optimizes multiple ML models
    """

    def __init__(self, config_path: str = 'config.yaml'):
        """Initialize model trainer with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.models = {}
        self.best_models = {}
        self.training_times = {}
        self.cv_scores = {}
        self.scaler = StandardScaler()

    def prepare_data(self, df: pd.DataFrame) -> Tuple:
        """
        Prepare data for training

        Args:
            df: DataFrame with features and Label column

        Returns:
            X_train, X_test, y_train, y_test, feature_names
        """
        logger.info("Preparing data for training...")

        # Separate features and labels
        # Exclude non-feature columns
        exclude_cols = ['url', 'Label', 'dataset_source', 'url_normalized']
        feature_cols = [col for col in df.columns if col not in exclude_cols]

        X = df[feature_cols]
        y = df['Label']

        # Handle missing values
        X = X.fillna(0)

        # Ensure all feature columns are numeric (drop any non-numeric columns)
        non_numeric_cols = X.select_dtypes(include=['object']).columns.tolist()
        if non_numeric_cols:
            logger.warning(f"Dropping {len(non_numeric_cols)} non-numeric columns: {non_numeric_cols}")
            X = X.select_dtypes(include=[np.number])
            feature_cols = X.columns.tolist()

        logger.info(f"Features shape: {X.shape}")
        logger.info(f"Labels shape: {y.shape}")
        logger.info(f"Number of features: {len(feature_cols)}")

        # Split data
        test_size = self.config['training']['test_size']
        random_state = self.config['training']['random_state']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        logger.info(f"Training set: {X_train.shape}")
        logger.info(f"Test set: {X_test.shape}")
        logger.info(f"Train label distribution: {y_train.value_counts().to_dict()}")
        logger.info(f"Test label distribution: {y_test.value_counts().to_dict()}")

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Convert back to DataFrame to maintain feature names
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=feature_cols)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=feature_cols)

        return X_train_scaled, X_test_scaled, y_train, y_test, feature_cols

    def train_random_forest(self, X_train, y_train) -> RandomForestClassifier:
        """Train Random Forest with optimized parameters (no GridSearch for speed)"""
        logger.info("Training Random Forest...")

        # Use best parameters directly (no GridSearch) for 10x faster training
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=self.config['training']['random_state'],
            n_jobs=self.config['training']['n_jobs'],
            verbose=0
        )

        start_time = time.time()
        rf.fit(X_train, y_train)
        self.training_times['random_forest'] = time.time() - start_time

        logger.info(f"Training time: {self.training_times['random_forest']:.2f}s")

        return rf

    def train_xgboost(self, X_train, y_train) -> XGBClassifier:
        """Train XGBoost with optimized parameters (no GridSearch for speed)"""
        logger.info("Training XGBoost...")

        # Convert DataFrame to numpy array for XGBoost compatibility
        X_train_np = X_train.values if hasattr(X_train, 'values') else X_train
        y_train_np = y_train.values if hasattr(y_train, 'values') else y_train

        # Use best parameters directly (no GridSearch) for 10x faster training
        xgb = XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=self.config['training']['random_state'],
            n_jobs=self.config['training']['n_jobs'],
            use_label_encoder=False,
            eval_metric='logloss',
            verbosity=0
        )

        start_time = time.time()
        xgb.fit(X_train_np, y_train_np)
        self.training_times['xgboost'] = time.time() - start_time

        logger.info(f"Training time: {self.training_times['xgboost']:.2f}s")

        return xgb

    def train_logistic_regression(self, X_train, y_train) -> LogisticRegression:
        """Train Logistic Regression with GridSearchCV"""
        logger.info("Training Logistic Regression...")

        param_grid = {
            'C': self.config['models']['logistic_regression']['C'],
            'penalty': self.config['models']['logistic_regression']['penalty'],
            'solver': self.config['models']['logistic_regression']['solver']
        }

        lr = LogisticRegression(
            random_state=self.config['training']['random_state'],
            max_iter=self.config['models']['logistic_regression']['max_iter'],
            n_jobs=self.config['training']['n_jobs']
        )

        start_time = time.time()

        grid_search = GridSearchCV(
            lr, param_grid,
            cv=self.config['training']['cv_folds'],
            scoring='accuracy',
            n_jobs=self.config['training']['n_jobs'],
            verbose=1
        )

        grid_search.fit(X_train, y_train)

        self.training_times['logistic_regression'] = time.time() - start_time

        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
        logger.info(f"Training time: {self.training_times['logistic_regression']:.2f}s")

        return grid_search.best_estimator_

    def train_decision_tree(self, X_train, y_train) -> DecisionTreeClassifier:
        """Train Decision Tree"""
        logger.info("Training Decision Tree...")

        start_time = time.time()

        dt = DecisionTreeClassifier(
            random_state=self.config['training']['random_state'],
            max_depth=20,
            min_samples_split=5
        )

        dt.fit(X_train, y_train)

        self.training_times['decision_tree'] = time.time() - start_time

        logger.info(f"Training time: {self.training_times['decision_tree']:.2f}s")

        return dt

    def train_svm(self, X_train, y_train) -> SVC:
        """Train SVM with GridSearchCV"""
        logger.info("Training SVM...")

        param_grid = {
            'C': self.config['models']['svm']['C'],
            'kernel': self.config['models']['svm']['kernel'],
            'gamma': self.config['models']['svm']['gamma']
        }

        svm = SVC(
            random_state=self.config['training']['random_state'],
            probability=True
        )

        start_time = time.time()

        grid_search = GridSearchCV(
            svm, param_grid,
            cv=self.config['training']['cv_folds'],
            scoring='accuracy',
            n_jobs=self.config['training']['n_jobs'],
            verbose=1
        )

        grid_search.fit(X_train, y_train)

        self.training_times['svm'] = time.time() - start_time

        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
        logger.info(f"Training time: {self.training_times['svm']:.2f}s")

        return grid_search.best_estimator_

    def train_neural_network(self, X_train, y_train) -> MLPClassifier:
        """Train Neural Network with GridSearchCV"""
        logger.info("Training Neural Network...")

        param_grid = {
            'hidden_layer_sizes': self.config['models']['neural_network']['hidden_layer_sizes'],
            'activation': self.config['models']['neural_network']['activation'],
            'alpha': self.config['models']['neural_network']['alpha']
        }

        mlp = MLPClassifier(
            random_state=self.config['training']['random_state'],
            max_iter=self.config['models']['neural_network']['max_iter'],
            learning_rate='adaptive'
        )

        start_time = time.time()

        grid_search = GridSearchCV(
            mlp, param_grid,
            cv=self.config['training']['cv_folds'],
            scoring='accuracy',
            n_jobs=self.config['training']['n_jobs'],
            verbose=1
        )

        grid_search.fit(X_train, y_train)

        self.training_times['neural_network'] = time.time() - start_time

        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
        logger.info(f"Training time: {self.training_times['neural_network']:.2f}s")

        return grid_search.best_estimator_

    def train_lightgbm(self, X_train, y_train) -> LGBMClassifier:
        """Train LightGBM"""
        logger.info("Training LightGBM...")

        start_time = time.time()

        lgbm = LGBMClassifier(
            random_state=self.config['training']['random_state'],
            n_estimators=200,
            max_depth=7,
            learning_rate=0.1,
            n_jobs=self.config['training']['n_jobs'],
            verbose=-1
        )

        lgbm.fit(X_train, y_train)

        self.training_times['lightgbm'] = time.time() - start_time

        logger.info(f"Training time: {self.training_times['lightgbm']:.2f}s")

        return lgbm

    def create_ensemble(self, models: Dict) -> VotingClassifier:
        """Create ensemble voting classifier from available models"""
        logger.info("Creating ensemble model...")

        # Use only available models
        estimators = []
        if 'random_forest' in models:
            estimators.append(('rf', models['random_forest']))
        if 'xgboost' in models:
            estimators.append(('xgb', models['xgboost']))
        if 'neural_network' in models:
            estimators.append(('mlp', models['neural_network']))
        if 'logistic_regression' in models:
            estimators.append(('lr', models['logistic_regression']))

        if len(estimators) < 2:
            raise ValueError("Need at least 2 models to create ensemble")

        logger.info(f"Creating ensemble from {len(estimators)} models: {[name for name, _ in estimators]}")

        ensemble = VotingClassifier(
            estimators=estimators,
            voting='soft',
            n_jobs=self.config['training']['n_jobs']
        )

        return ensemble

    def train_all_models(self, X_train, X_test, y_train, y_test, fast_mode=True) -> Dict:
        """
        Train models

        Args:
            fast_mode: If True, only trains Random Forest and XGBoost (5-10 mins)
                      If False, trains all 7 models (20-30 mins)

        Returns:
            Dictionary of trained models
        """
        logger.info("=" * 80)
        if fast_mode:
            logger.info("TRAINING MODELS (FAST MODE - 2 Models)")
            logger.info("Models: Random Forest, XGBoost")
        else:
            logger.info("TRAINING ALL MODELS (FULL MODE - 7 Models)")
        logger.info("=" * 80)

        models = {}

        # Train core models (always trained)
        try:
            models['random_forest'] = self.train_random_forest(X_train, y_train)
        except Exception as e:
            logger.error(f"Error training Random Forest: {e}")

        try:
            models['xgboost'] = self.train_xgboost(X_train, y_train)
        except Exception as e:
            logger.error(f"Error training XGBoost: {e}")

        # Train additional models only if not in fast mode
        if not fast_mode:
            try:
                models['logistic_regression'] = self.train_logistic_regression(X_train, y_train)
            except Exception as e:
                logger.error(f"Error training Logistic Regression: {e}")

            try:
                models['decision_tree'] = self.train_decision_tree(X_train, y_train)
            except Exception as e:
                logger.error(f"Error training Decision Tree: {e}")

            try:
                models['svm'] = self.train_svm(X_train, y_train)
            except Exception as e:
                logger.error(f"Error training SVM: {e}")

            try:
                models['neural_network'] = self.train_neural_network(X_train, y_train)
            except Exception as e:
                logger.error(f"Error training Neural Network: {e}")

            try:
                models['lightgbm'] = self.train_lightgbm(X_train, y_train)
            except Exception as e:
                logger.error(f"Error training LightGBM: {e}")

        # Create ensemble from trained models
        try:
            ensemble = self.create_ensemble(models)
            logger.info("Fitting ensemble model...")
            start_time = time.time()
            ensemble.fit(X_train, y_train)
            self.training_times['ensemble'] = time.time() - start_time
            models['ensemble'] = ensemble
        except Exception as e:
            logger.error(f"Error creating ensemble: {e}")

        logger.info("=" * 80)
        logger.info("MODEL TRAINING COMPLETE")
        logger.info(f"Total models trained: {len(models)}")
        logger.info("=" * 80)

        return models

    def save_models(self, models: Dict, feature_names: List[str]):
        """Save trained models to disk"""
        logger.info("Saving models...")

        os.makedirs('models', exist_ok=True)

        for name, model in models.items():
            filename = f'models/{name}_model.pkl'
            joblib.dump(model, filename)
            logger.info(f"Saved {name} to {filename}")

        # Save scaler
        joblib.dump(self.scaler, 'models/feature_scaler.pkl')
        logger.info("Saved feature scaler")

        # Save feature names
        joblib.dump(feature_names, 'models/feature_names.pkl')
        logger.info("Saved feature names")

        # Save training times
        joblib.dump(self.training_times, 'models/training_times.pkl')
        logger.info("Saved training times")

    def load_models(self) -> Dict:
        """Load saved models from disk"""
        logger.info("Loading models...")

        models = {}

        model_files = [
            'random_forest_model.pkl',
            'xgboost_model.pkl',
            'logistic_regression_model.pkl',
            'decision_tree_model.pkl',
            'svm_model.pkl',
            'neural_network_model.pkl',
            'lightgbm_model.pkl',
            'ensemble_model.pkl'
        ]

        for filename in model_files:
            path = f'models/{filename}'
            if os.path.exists(path):
                name = filename.replace('_model.pkl', '')
                models[name] = joblib.load(path)
                logger.info(f"Loaded {name}")

        # Load scaler
        if os.path.exists('models/feature_scaler.pkl'):
            self.scaler = joblib.load('models/feature_scaler.pkl')
            logger.info("Loaded feature scaler")

        return models


if __name__ == '__main__':
    # Test model training
    logger.info("Model trainer module loaded successfully")
