"""
PhishTank Dataset Loader
Downloads and integrates PhishTank verified phishing URLs
PhishTank provides real-time, community-verified phishing data
"""

import requests
import json
import csv
import os
import gzip
from datetime import datetime
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishTankLoader:
    """
    Load and process PhishTank verified phishing URLs
    """

    def __init__(self, data_dir: str = 'data'):
        self.data_dir = data_dir
        self.phishtank_url = "http://data.phishtank.com/data/online-valid.json"
        self.phishtank_csv_url = "http://data.phishtank.com/data/online-valid.csv"

        # Create data directory if needed
        os.makedirs(data_dir, exist_ok=True)

    def download_phishtank_data(self, format='csv') -> str:
        """
        Download latest PhishTank data
        Returns path to downloaded file
        """
        logger.info("Downloading PhishTank verified phishing URLs...")

        try:
            if format == 'json':
                url = self.phishtank_url
                filename = f'phishtank_{datetime.now().strftime("%Y%m%d")}.json'
            else:
                url = self.phishtank_csv_url
                filename = f'phishtank_{datetime.now().strftime("%Y%m%d")}.csv'

            filepath = os.path.join(self.data_dir, filename)

            # Check if already downloaded today
            if os.path.exists(filepath):
                logger.info(f"PhishTank data already downloaded: {filepath}")
                return filepath

            # Download
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # Save
            with open(filepath, 'wb') as f:
                f.write(response.content)

            logger.info(f"Downloaded {len(response.content)} bytes to {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error downloading PhishTank data: {e}")

            # Try to use existing file
            existing_files = [f for f in os.listdir(self.data_dir) if f.startswith('phishtank_') and f.endswith(f'.{format}')]
            if existing_files:
                latest = max(existing_files)
                logger.info(f"Using existing PhishTank data: {latest}")
                return os.path.join(self.data_dir, latest)

            raise

    def load_phishtank_urls(self, max_urls: int = 10000) -> List[Dict]:
        """
        Load PhishTank URLs
        Returns list of phishing URL dictionaries
        """
        try:
            # Download data
            filepath = self.download_phishtank_data(format='csv')

            logger.info(f"Loading PhishTank URLs from {filepath}...")

            urls = []

            # Read CSV
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= max_urls:
                        break

                    try:
                        url_data = {
                            'url': row.get('url', ''),
                            'phish_id': row.get('phish_id', ''),
                            'phish_detail_url': row.get('phish_detail_url', ''),
                            'submission_time': row.get('submission_time', ''),
                            'verified': row.get('verified', '') == 'yes',
                            'verification_time': row.get('verification_time', ''),
                            'online': row.get('online', '') == 'yes',
                            'target': row.get('target', ''),
                            'label': 1  # Phishing
                        }

                        if url_data['url']:
                            urls.append(url_data)

                    except Exception as e:
                        logger.warning(f"Error parsing row {i}: {e}")
                        continue

            logger.info(f"Loaded {len(urls)} PhishTank phishing URLs")
            return urls

        except Exception as e:
            logger.error(f"Error loading PhishTank URLs: {e}")
            return []

    def create_training_dataset(self, phishing_urls: List[Dict],
                                legitimate_urls: List[str] = None,
                                output_file: str = 'phishtank_training.csv') -> str:
        """
        Create balanced training dataset with PhishTank phishing + legitimate URLs
        """
        logger.info("Creating training dataset...")

        output_path = os.path.join(self.data_dir, output_file)

        # If no legitimate URLs provided, use common legitimate domains
        if legitimate_urls is None:
            legitimate_urls = self._get_default_legitimate_urls()

        # Balance dataset
        num_phishing = len(phishing_urls)
        num_legitimate = min(len(legitimate_urls), num_phishing)

        logger.info(f"Dataset: {num_phishing} phishing + {num_legitimate} legitimate = {num_phishing + num_legitimate} total")

        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'label'])  # Header

            # Write phishing URLs
            for phish in phishing_urls:
                writer.writerow([phish['url'], 1])

            # Write legitimate URLs
            for i, legit in enumerate(legitimate_urls[:num_legitimate]):
                writer.writerow([legit, 0])

        logger.info(f"Training dataset saved to: {output_path}")
        return output_path

    def _get_default_legitimate_urls(self) -> List[str]:
        """
        Get default list of legitimate URLs for training
        """
        legitimate = [
            # Top websites (Alexa/Tranco top 1000)
            'https://www.google.com',
            'https://www.youtube.com',
            'https://www.facebook.com',
            'https://www.twitter.com',
            'https://www.instagram.com',
            'https://www.linkedin.com',
            'https://www.reddit.com',
            'https://www.wikipedia.org',
            'https://www.amazon.com',
            'https://www.ebay.com',
            'https://www.netflix.com',
            'https://www.microsoft.com',
            'https://www.apple.com',
            'https://www.adobe.com',
            'https://www.github.com',
            'https://www.stackoverflow.com',
            'https://www.bbc.com',
            'https://www.cnn.com',
            'https://www.nytimes.com',
            'https://www.washingtonpost.com',

            # Banks (official sites)
            'https://www.chase.com',
            'https://www.bankofamerica.com',
            'https://www.wellsfargo.com',
            'https://www.citibank.com',
            'https://www.capitalone.com',
            'https://www.usbank.com',
            'https://www.pnc.com',
            'https://www.tdbank.com',

            # Tech companies
            'https://www.ibm.com',
            'https://www.oracle.com',
            'https://www.salesforce.com',
            'https://www.sap.com',
            'https://www.vmware.com',
            'https://www.cisco.com',
            'https://www.dell.com',
            'https://www.hp.com',
            'https://www.intel.com',
            'https://www.amd.com',
            'https://www.nvidia.com',

            # E-commerce
            'https://www.walmart.com',
            'https://www.target.com',
            'https://www.bestbuy.com',
            'https://www.homedepot.com',
            'https://www.lowes.com',
            'https://www.costco.com',
            'https://www.ikea.com',
            'https://www.etsy.com',
            'https://www.aliexpress.com',
            'https://www.alibaba.com',

            # Travel
            'https://www.expedia.com',
            'https://www.booking.com',
            'https://www.airbnb.com',
            'https://www.tripadvisor.com',
            'https://www.hotels.com',
            'https://www.kayak.com',
            'https://www.priceline.com',

            # Government
            'https://www.usa.gov',
            'https://www.irs.gov',
            'https://www.uscis.gov',
            'https://www.usps.com',
            'https://www.socialsecurity.gov',

            # Universities
            'https://www.mit.edu',
            'https://www.stanford.edu',
            'https://www.harvard.edu',
            'https://www.berkeley.edu',
            'https://www.caltech.edu',
            'https://www.princeton.edu',
            'https://www.yale.edu',
            'https://www.columbia.edu',

            # News
            'https://www.reuters.com',
            'https://www.bloomberg.com',
            'https://www.forbes.com',
            'https://www.cnbc.com',
            'https://www.theguardian.com',
            'https://www.wsj.com',

            # Email providers
            'https://mail.google.com',
            'https://outlook.live.com',
            'https://mail.yahoo.com',
            'https://www.icloud.com',
            'https://www.protonmail.com',

            # Cloud providers
            'https://aws.amazon.com',
            'https://azure.microsoft.com',
            'https://cloud.google.com',
            'https://www.digitalocean.com',
            'https://www.heroku.com',
            'https://www.cloudflare.com',

            # Developer tools
            'https://www.npmjs.com',
            'https://www.pypi.org',
            'https://www.docker.com',
            'https://www.kubernetes.io',
            'https://www.jenkins.io',
            'https://www.gitlab.com',
            'https://bitbucket.org',

            # Social/Communication
            'https://www.discord.com',
            'https://www.slack.com',
            'https://www.zoom.us',
            'https://www.teams.microsoft.com',
            'https://www.telegram.org',
            'https://www.whatsapp.com',
            'https://www.snapchat.com',
            'https://www.tiktok.com',
            'https://www.pinterest.com',
            'https://www.tumblr.com',

            # Streaming
            'https://www.spotify.com',
            'https://www.soundcloud.com',
            'https://www.twitch.tv',
            'https://www.hulu.com',
            'https://www.disneyplus.com',
            'https://www.hbomax.com',
            'https://www.paramount.com',

            # Gaming
            'https://store.steampowered.com',
            'https://www.epicgames.com',
            'https://www.blizzard.com',
            'https://www.ea.com',
            'https://www.playstation.com',
            'https://www.xbox.com',
            'https://www.nintendo.com',
            'https://www.roblox.com',
            'https://www.minecraft.net',

            # Payment
            'https://www.paypal.com',
            'https://www.stripe.com',
            'https://www.square.com',
            'https://www.venmo.com',

            # Education
            'https://www.coursera.org',
            'https://www.udemy.com',
            'https://www.edx.org',
            'https://www.khanacademy.org',
            'https://www.duolingo.com',
            'https://www.skillshare.com',

            # Health
            'https://www.webmd.com',
            'https://www.mayoclinic.org',
            'https://www.clevelandclinic.org',
            'https://www.nih.gov',
            'https://www.cdc.gov',
            'https://www.who.int',
        ]

        # Generate more variations
        additional = []
        for url in legitimate[:50]:
            # Add www and non-www versions
            if 'www.' in url:
                additional.append(url.replace('www.', ''))
            else:
                domain = url.replace('https://', '')
                additional.append(f'https://www.{domain}')

        return legitimate + additional

    def merge_with_existing_dataset(self, phishtank_file: str, existing_file: str,
                                    output_file: str = 'merged_training.csv') -> str:
        """
        Merge PhishTank data with existing training data
        """
        logger.info("Merging datasets...")

        output_path = os.path.join(self.data_dir, output_file)

        urls_seen = set()
        total_count = 0

        with open(output_path, 'w', newline='', encoding='utf-8') as out_f:
            writer = csv.writer(out_f)
            writer.writerow(['url', 'label'])

            # Read PhishTank data
            logger.info(f"Reading PhishTank data from {phishtank_file}...")
            with open(phishtank_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = row['url']
                    if url not in urls_seen:
                        writer.writerow([url, row['label']])
                        urls_seen.add(url)
                        total_count += 1

            # Read existing data
            if os.path.exists(existing_file):
                logger.info(f"Reading existing data from {existing_file}...")
                with open(existing_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        url = row.get('url', '')
                        label = row.get('label', row.get('Label', '0'))
                        if url and url not in urls_seen:
                            writer.writerow([url, label])
                            urls_seen.add(url)
                            total_count += 1
            else:
                logger.warning(f"Existing file not found: {existing_file}")

        logger.info(f"Merged dataset saved to: {output_path}")
        logger.info(f"Total unique URLs: {total_count}")

        return output_path


if __name__ == '__main__':
    # Example usage
    loader = PhishTankLoader()

    # Download and load PhishTank data
    phishing_urls = loader.load_phishtank_urls(max_urls=5000)
    print(f"\nLoaded {len(phishing_urls)} phishing URLs from PhishTank")

    if phishing_urls:
        print("\nSample phishing URLs:")
        for url in phishing_urls[:5]:
            print(f"  - {url['url'][:80]}...")
            print(f"    Target: {url.get('target', 'Unknown')}")
            print(f"    Verified: {url.get('verified', False)}")

        # Create training dataset
        training_file = loader.create_training_dataset(phishing_urls, output_file='phishtank_training.csv')
        print(f"\nTraining dataset created: {training_file}")

        # Merge with existing data if available
        existing_file = 'data/Dataset.csv'
        if os.path.exists(existing_file):
            merged_file = loader.merge_with_existing_dataset(training_file, existing_file)
            print(f"Merged dataset created: {merged_file}")
