import urllib.request as request
from src.phishingdetection.utils.common_functionality import get_size
from src.phishingdetection import logger
from src.phishingdetection.entity.config_entity import DataIngestionConfig
import pandas as pd
import os



class DataIngestion:
    def __init__(self, config: DataIngestionConfig):
        self.config = config



    def collect_phishing_data(self):
        if not os.path.exists(self.config.phishing_data_file):
            
            url = self.config.source_URL_phishing
            df = pd.read_csv(url)
            df.to_csv(self.config.phishing_data_file,index=False)
            
            logger.info("Phishing data Saved!")
        else:
            logger.info(f"File already exists of size: {get_size(Path(self.config.local_data_file))}")


    def collect_legit_data(self):
        if not os.path.exists(self.config.legit_data_file):
            
            url = self.config.source_URL_legit
            df = pd.read_csv(url)
            df.to_csv(self.config.legit_data_file,index=False)
            
            logger.info("Legit data Saved!")
        else:
            logger.info(f"File already exists of size: {get_size(Path(self.config.local_data_file))}")

    
    def collect_ranking_data(self):
        if not os.path.exists(self.config.ranking_data_file):
            
            url = self.config.source_URL_ranking
            export_path = 'https://drive.google.com/uc?export=download&id='+url.split('/')[-2]
            df = pd.read_csv(export_path)
            df.to_csv(self.config.ranking_data_file,index=False)
            
            logger.info("Ranking data Saved!")
        else:
            logger.info(f"File already exists of size: {get_size(Path(self.config.local_data_file))}")