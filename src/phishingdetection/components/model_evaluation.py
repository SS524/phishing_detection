from src.phishingdetection.utils.common_functionality import load_object,save_json
import pandas as pd
from sklearn.metrics import accuracy_score
from src.phishingdetection.entity.config_entity import ModelEvaluationConfig
import os
from pathlib import Path


class ModelEvaluation:
    def __init__(self, config: ModelEvaluationConfig):
        self.config = config


    
    def evaluate(self, model_path, test_data_path):
        
        trained_model = load_object(model_path)
        final_data = pd.read_pickle(test_data_path)
        X_test = final_data['X_test']
        y_test = final_data['y_test']

        preds = trained_model.predict(X_test)

        accuracy = accuracy_score(y_test,preds)

        score_dic={
            'accuracy': accuracy
        }

        save_json(Path('scores.json'),score_dic)
        
          


