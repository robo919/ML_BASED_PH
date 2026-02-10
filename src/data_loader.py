"""
Data Loader Module for ML Phishing URL Detection System
Handles loading, merging, and preprocessing of multiple phishing datasets
"""

import pandas as pd
import numpy as np
import os
import logging
from typing import Tuple, Optional
import yaml
import requests
from tqdm import tqdm

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DataLoader:
    """
    Comprehensive data loader for phishing URL datasets
    Handles multiple dataset formats and merging strategies
    """

    def __init__(self, config_path: str = 'config.yaml'):
        """Initialize data loader with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.dataset1_path = self.config['data']['dataset1']
        self.dataset2_path = self.config['data']['dataset2']
        self.combined_path = self.config['data']['combined']

    def load_dataset1(self) -> pd.DataFrame:
        """
        Load Dataset 1 (URL-Phish from Mendeley)
        116,600 rows with 22 features
        """
        logger.info(f"Loading Dataset 1 from {self.dataset1_path}")
        try:
            df = pd.read_csv(self.dataset1_path, low_memory=False)
            logger.info(f"Dataset 1 loaded: {len(df)} rows, {len(df.columns)} columns")
            logger.info(f"Columns: {df.columns.tolist()}")

            # Standardize label column name
            if 'label' in df.columns:
                df.rename(columns={'label': 'Label'}, inplace=True)

            # Add dataset source
            df['dataset_source'] = 'dataset1'

            return df
        except Exception as e:
            logger.error(f"Error loading Dataset 1: {e}")
            raise

    def load_dataset2(self) -> pd.DataFrame:
        """
        Load Dataset 2 (LegitPhish from Mendeley)
        101,219 rows with 18 features
        """
        logger.info(f"Loading Dataset 2 from {self.dataset2_path}")
        try:
            df = pd.read_csv(self.dataset2_path, low_memory=False)
            logger.info(f"Dataset 2 loaded: {len(df)} rows, {len(df.columns)} columns")
            logger.info(f"Columns: {df.columns.tolist()}")

            # Standardize label column name
            if 'ClassLabel' in df.columns:
                df.rename(columns={'ClassLabel': 'Label'}, inplace=True)

            # Standardize URL column name
            if 'URL' in df.columns:
                df.rename(columns={'URL': 'url'}, inplace=True)

            # Add dataset source
            df['dataset_source'] = 'dataset2'

            return df
        except Exception as e:
            logger.error(f"Error loading Dataset 2: {e}")
            raise

    def merge_datasets(self, df1: pd.DataFrame, df2: pd.DataFrame) -> pd.DataFrame:
        """
        Intelligently merge two datasets with different feature sets

        Strategy:
        1. Identify common features
        2. Keep URL and Label columns from both
        3. Merge on URL to combine features
        4. Handle missing values appropriately
        """
        logger.info("Merging datasets intelligently...")

        # Ensure both have url and Label columns
        if 'url' not in df1.columns or 'url' not in df2.columns:
            raise ValueError("Both datasets must have 'url' column")

        if 'Label' not in df1.columns or 'Label' not in df2.columns:
            raise ValueError("Both datasets must have 'Label' column")

        # Normalize URLs for better matching
        df1['url_normalized'] = df1['url'].str.lower().str.strip()
        df2['url_normalized'] = df2['url'].str.lower().str.strip()

        # Remove duplicates within each dataset
        df1_dedup = df1.drop_duplicates(subset=['url_normalized'], keep='first')
        df2_dedup = df2.drop_duplicates(subset=['url_normalized'], keep='first')

        logger.info(f"Dataset 1 after deduplication: {len(df1_dedup)} rows")
        logger.info(f"Dataset 2 after deduplication: {len(df2_dedup)} rows")

        # Find common URLs
        common_urls = set(df1_dedup['url_normalized']) & set(df2_dedup['url_normalized'])
        logger.info(f"Found {len(common_urls)} common URLs between datasets")

        # Merge strategy: outer join to keep all URLs
        # For common URLs, prefer features from the dataset with more features
        merged = pd.merge(
            df1_dedup,
            df2_dedup,
            on='url_normalized',
            how='outer',
            suffixes=('_d1', '_d2')
        )

        # Reconcile URL and Label columns
        merged['url'] = merged['url_d1'].fillna(merged['url_d2'])
        merged['Label'] = merged['Label_d1'].fillna(merged['Label_d2'])

        # Handle conflicting labels (if URL exists in both but with different labels)
        conflicting = merged[(merged['Label_d1'].notna()) &
                            (merged['Label_d2'].notna()) &
                            (merged['Label_d1'] != merged['Label_d2'])]

        if len(conflicting) > 0:
            logger.warning(f"Found {len(conflicting)} URLs with conflicting labels. Using majority vote.")
            # For conflicts, use the phishing label (safer approach)
            merged.loc[conflicting.index, 'Label'] = 1

        # Drop redundant columns
        cols_to_drop = ['url_d1', 'url_d2', 'Label_d1', 'Label_d2', 'url_normalized']
        merged.drop(columns=[col for col in cols_to_drop if col in merged.columns], inplace=True)

        logger.info(f"Merged dataset: {len(merged)} rows, {len(merged.columns)} columns")

        # Display label distribution
        label_dist = merged['Label'].value_counts()
        logger.info(f"Label distribution:\n{label_dist}")
        logger.info(f"Legitimate URLs: {label_dist.get(0, 0)}")
        logger.info(f"Phishing URLs: {label_dist.get(1, 0)}")

        return merged

    def download_openphish(self) -> Optional[pd.DataFrame]:
        """Download from OpenPhish feed (free, no API key required)"""
        logger.info("Downloading OpenPhish feed...")
        try:
            response = requests.get('https://openphish.com/feed.txt', timeout=30)
            if response.status_code == 200:
                urls = [line.strip() for line in response.text.split('\n') if line.strip()]
                logger.info(f"Downloaded {len(urls)} phishing URLs from OpenPhish")
                return pd.DataFrame({
                    'url': urls,
                    'Label': 1,
                    'dataset_source': 'openphish'
                })
        except Exception as e:
            logger.warning(f"Error downloading OpenPhish: {e}")
        return None

    def download_phishtank_free(self) -> Optional[pd.DataFrame]:
        """Download PhishTank free public feed (no API key required)"""
        logger.info("Downloading PhishTank free feed...")
        try:
            response = requests.get('http://data.phishtank.com/data/online-valid.json', timeout=60)
            if response.status_code == 200:
                data = response.json()
                urls = [entry['url'] for entry in data if 'url' in entry]
                logger.info(f"Downloaded {len(urls)} phishing URLs from PhishTank")
                return pd.DataFrame({
                    'url': urls,
                    'Label': 1,
                    'dataset_source': 'phishtank'
                })
        except Exception as e:
            logger.warning(f"Error downloading PhishTank: {e}")
        return None

    def download_urlhaus(self) -> Optional[pd.DataFrame]:
        """Download from URLhaus (abuse.ch) - free malware URL database"""
        logger.info("Downloading URLhaus feed...")
        try:
            response = requests.get('https://urlhaus.abuse.ch/downloads/csv_recent/', timeout=30)
            if response.status_code == 200:
                from io import StringIO
                lines = [l for l in response.text.split('\n') if l and not l.startswith('#')]
                csv_data = StringIO('\n'.join(lines))
                df = pd.read_csv(csv_data, quotechar='"', on_bad_lines='skip')

                if 'url' in df.columns:
                    urls = df['url'].tolist()
                elif len(df.columns) > 2:
                    urls = df.iloc[:, 2].tolist()
                else:
                    return None

                urls = [str(u).strip() for u in urls if str(u).strip() and str(u) != 'nan']
                logger.info(f"Downloaded {len(urls)} malicious URLs from URLhaus")
                return pd.DataFrame({
                    'url': urls,
                    'Label': 1,
                    'dataset_source': 'urlhaus'
                })
        except Exception as e:
            logger.warning(f"Error downloading URLhaus: {e}")
        return None

    def download_legitimate_urls(self) -> Optional[pd.DataFrame]:
        """Download legitimate URLs from Tranco top sites (free)"""
        logger.info("Downloading legitimate URLs from Tranco list...")
        try:
            import zipfile
            from io import BytesIO

            response = requests.get('https://tranco-list.eu/top-1m.csv.zip', timeout=60, stream=True)
            if response.status_code == 200:
                zip_file = zipfile.ZipFile(BytesIO(response.content))
                csv_filename = zip_file.namelist()[0]

                with zip_file.open(csv_filename) as f:
                    df = pd.read_csv(f, names=['rank', 'domain'])

                top_domains = df.head(10000)['domain'].tolist()
                urls = [f'https://{domain}' for domain in top_domains]
                logger.info(f"Downloaded {len(urls)} legitimate URLs from Tranco")
                return pd.DataFrame({
                    'url': urls,
                    'Label': 0,
                    'dataset_source': 'tranco_top'
                })
        except Exception as e:
            logger.warning(f"Error downloading Tranco list: {e}")
        return None

    def download_supplementary_data(self) -> Optional[pd.DataFrame]:
        """
        Download supplementary phishing data from multiple free sources

        Sources:
        1. OpenPhish (free, updated daily)
        2. PhishTank (free public feed)
        3. URLhaus (malware URLs)
        4. Tranco (legitimate top sites)
        """
        logger.info("Downloading from multiple free sources...")

        all_dfs = []
        import time

        # Download from all sources with delays
        sources = [
            ('OpenPhish', self.download_openphish),
            ('PhishTank', self.download_phishtank_free),
            ('URLhaus', self.download_urlhaus),
            ('Tranco', self.download_legitimate_urls)
        ]

        for source_name, download_func in sources:
            df = download_func()
            if df is not None:
                all_dfs.append(df)
            time.sleep(2)  # Be respectful to servers

        if not all_dfs:
            logger.warning("Failed to download any supplementary data")
            return None

        # Combine all sources
        combined = pd.concat(all_dfs, ignore_index=True)
        logger.info(f"Combined {len(combined)} URLs from {len(all_dfs)} sources")

        return combined

    def add_supplementary_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add supplementary data to the main dataset
        """
        supp_df = self.download_supplementary_data()

        if supp_df is not None:
            logger.info(f"Adding {len(supp_df)} supplementary URLs...")

            # Remove duplicates with existing data
            existing_urls = set(df['url'].str.lower().str.strip())
            supp_df = supp_df[~supp_df['url'].str.lower().str.strip().isin(existing_urls)]

            logger.info(f"After deduplication: {len(supp_df)} new URLs to add")

            if len(supp_df) > 0:
                # Concatenate
                df = pd.concat([df, supp_df], ignore_index=True)
                logger.info(f"Dataset size after adding supplementary data: {len(df)}")

        return df

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean and preprocess the merged dataset
        """
        logger.info("Cleaning data...")

        # Remove rows with missing URLs
        initial_len = len(df)
        df = df.dropna(subset=['url'])
        logger.info(f"Removed {initial_len - len(df)} rows with missing URLs")

        # Remove rows with missing labels
        initial_len = len(df)
        df = df.dropna(subset=['Label'])
        logger.info(f"Removed {initial_len - len(df)} rows with missing labels")

        # Ensure labels are binary (0 or 1)
        df['Label'] = df['Label'].astype(int)
        df = df[df['Label'].isin([0, 1])]

        # Remove exact duplicate URLs
        initial_len = len(df)
        df = df.drop_duplicates(subset=['url'], keep='first')
        logger.info(f"Removed {initial_len - len(df)} duplicate URLs")

        # Reset index
        df = df.reset_index(drop=True)

        logger.info(f"Cleaned dataset: {len(df)} rows")

        return df

    def load_and_merge_all(self, include_supplementary: bool = True) -> pd.DataFrame:
        """
        Main method to load and merge all datasets

        Args:
            include_supplementary: Whether to download and add supplementary data

        Returns:
            Merged and cleaned dataframe
        """
        logger.info("=" * 80)
        logger.info("LOADING AND MERGING ALL DATASETS")
        logger.info("=" * 80)

        # Load both main datasets
        df1 = self.load_dataset1()
        df2 = self.load_dataset2()

        # Merge datasets
        merged_df = self.merge_datasets(df1, df2)

        # Add supplementary data if requested
        if include_supplementary:
            merged_df = self.add_supplementary_data(merged_df)

        # Clean data
        merged_df = self.clean_data(merged_df)

        # Save combined dataset
        logger.info(f"Saving combined dataset to {self.combined_path}")
        merged_df.to_csv(self.combined_path, index=False)

        logger.info("=" * 80)
        logger.info("DATASET LOADING COMPLETE")
        logger.info(f"Total URLs: {len(merged_df)}")
        logger.info(f"Legitimate: {len(merged_df[merged_df['Label'] == 0])}")
        logger.info(f"Phishing: {len(merged_df[merged_df['Label'] == 1])}")
        logger.info("=" * 80)

        return merged_df

    def get_dataset_statistics(self, df: pd.DataFrame) -> dict:
        """
        Get comprehensive statistics about the dataset
        """
        stats = {
            'total_urls': len(df),
            'legitimate_urls': len(df[df['Label'] == 0]),
            'phishing_urls': len(df[df['Label'] == 1]),
            'phishing_ratio': len(df[df['Label'] == 1]) / len(df) if len(df) > 0 else 0,
            'num_features': len(df.columns) - 2,  # Excluding url and Label
            'missing_values': df.isnull().sum().sum(),
            'duplicate_urls': df['url'].duplicated().sum()
        }

        return stats


if __name__ == '__main__':
    # Test data loading
    loader = DataLoader()
    df = loader.load_and_merge_all(include_supplementary=False)

    stats = loader.get_dataset_statistics(df)
    print("\nDataset Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
