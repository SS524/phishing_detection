from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import RandomizedSearchCV
from src.phishingdetection.utils.common_functionality import load_object, save_object, get_size
from src.phishingdetection import logger
import pandas as pd
from src.phishingdetection.entity.config_entity import ModelBuildingConfig
import os



class ModelBuilding:
    def __init__(self, config: ModelBuildingConfig):
        self.config = config


    def train_model(self,final_data_path):
        
            
        final_data_for_training = pd.read_pickle(final_data_path)

        X_train = final_data_for_training['X_train']
        y_train = final_data_for_training['y_train']
    

        # models_dic = {
        #     'LogisticRegression': LogisticRegression(),
        #     'DecisionTreeClassifier': DecisionTreeClassifier(),
        #     'RandomForestClassifier': RandomForestClassifier(),
        #     'GradientBoostingClassifier': GradientBoostingClassifier(),
        #     'SVC': SVC()
        # }
        # model_performance = {
        #     'Models':[],
        #     'Best_score':[],
        #     'Best_params':[]
        # }
        # for k,v in models_dic.items():
        #     random_src = RandomizedSearchCV(estimator=v, param_distributions=read_yaml(PARAMS_FILE_PATH).to_dict()[k], cv=3, n_jobs=-1)
        #     random_src.fit(X_train,y_train)
        #     model_performance['Models'].append(random_src.best_estimator_)
        #     model_performance['Best_score'].append(random_src.best_score_)
        #     model_performance['Best_params'].append(random_src.best_params_)
            
        # model_performance_df = pd.DataFrame(model_performance)

        # best_record = model_performance_df[model_performance_df['Best_score']==max(model_performance_df['Best_score'])]

        # best_model = best_record.loc[:,'Models'].values[0]
        # best_score = best_record.loc[:,'Best_score'].values[0]
        # best_params = best_record.loc[:,'Best_params'].values[0]

        # print(best_model, best_score, best_params)

        # print(model_performance_df)


        model = LogisticRegression(solver='lbfgs', penalty='l2', C=0.01)

        model.fit(X_train,y_train)

        if not os.path.exists(self.config.trained_modl_file):
            save_object(self.config.trained_modl_file,model)
            logger.info('Trained model is saved')
        else:
            logger.info(f"File already exists of size: {get_size(Path(self.config.local_data_file))}")

            
            
