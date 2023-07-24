from src.phishingdetection.utils.common_functionality import get_size, save_object, load_object, featureExtraction
from src.phishingdetection import logger
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from src.phishingdetection.entity.config_entity import DataProcessingConfig
import os



class DataProcessing:
    def __init__(self, config: DataProcessingConfig):
        self.config = config


    
    def data_cleaning(self,phishing_data_path,legit_data_path):

        df1 = pd.read_csv(phishing_data_path)
        if df1['url'].isnull().sum()!=0:
            df1 = df1.dropna(axis=0)
        
        df1 = df1.drop_duplicates()
        phishing_df = df1.sample(n=3500,random_state=12).copy()
        phishing_df = phishing_df.reset_index(drop=True)

        legit_df = pd.read_csv(legit_data_path)

        
        df2 = pd.read_csv(legit_data_path)
        df2.columns = ['URLs']
        if df2['URLs'].isnull().sum()!=0:
            df2 = df2.dropna(axis=0)
        
        df2 = df2.drop_duplicates()
        legit_df = df2.sample(n=3500,random_state=12).copy()
        legit_df = legit_df.reset_index(drop=True)

        logger.info('Data cleaning done')


        return phishing_df,legit_df


    def feature_extraction(self,phishing_df,legit_df):

        feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Label']
        
        
        try:
            legi_features = []
            label = 0
            for i in range(0, 3500):
                url = legit_df['URLs'][i]
                legi_features.append(featureExtraction(url,label))
            
            legitimate = pd.DataFrame(legi_features, columns= feature_names)

        except Exception as e:
            logger.info(e)


        try:
            phish_features = []
            label = 1
            for i in range(0, 3500):
                url = phishing_df['url'][i]
                phish_features.append(featureExtraction(url,label))
        
            phishing = pd.DataFrame(phish_features, columns= feature_names)

        except Exception as e:
            logger.info(e)

        
        urldata = pd.concat([legitimate, phishing]).reset_index(drop=True)

        X = urldata.drop(['Domain','Label'],axis=1)
        y = urldata['Label']

        X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2,random_state=42)

        scaler = StandardScaler()

        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        final_data = {
            'X_train': X_train_scaled,
            'y_train':y_train,
            'X_test': X_test_scaled,
            'y_test': y_test
        }

        if not os.path.exists(self.config.final_data_file):
            save_object(self.config.final_data_file, final_data)
            logger.info('Final data is saved!')

        else:
            logger.info(f"File already exists of size: {get_size(Path(self.config.local_data_file))}")

