from src.phishingdetection.utils.common_functionality import load_object, featureExtraction
from sklearn.preprocessing import StandardScaler
import os
import pandas as pd


class PredictionPipeline:
    def __init__(self, url):
        self.url = url


    def predict(self):

        features = featureExtraction(self.url,0)
        features = features[1:-1]
        columns = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic']
        print(features)
        final_df = pd.DataFrame([features],columns=columns)
        scaler = load_object(os.path.join('artifacts','data_processing','scaling.pkl'))
        final_df_scaled = scaler.transform(final_df)
        print(final_df_scaled)
        
        model = load_object(os.path.join("artifacts","model_building","trained_model.pkl"))
    
        pred = model.predict(final_df_scaled)[0]




        return pred

