from src.phishingdetection.constants import *
from src.phishingdetection.utils.common_functionality import read_yaml, create_directories
from src.phishingdetection.entity.config_entity import DataIngestionConfig, DataProcessingConfig, ModelBuildingConfig, ModelEvaluationConfig

class ConfigurationManager:
    def __init__(
        self,
        config_filepath = CONFIG_FILE_PATH,
        params_filepath = PARAMS_FILE_PATH):

        self.config = read_yaml(config_filepath)
        self.params = read_yaml(params_filepath)

        create_directories([self.config.artifacts_root])


    
    def get_data_ingestion_config(self) -> DataIngestionConfig:
        config = self.config.data_ingestion

        create_directories([config.root_dir])

        data_ingestion_config = DataIngestionConfig(
            root_dir=config.root_dir,
            source_URL_phishing=config.source_URL_phishing,
            source_URL_legit=config.source_URL_legit,
            source_URL_ranking=config.source_URL_ranking,
            phishing_data_file=config.phishing_data_file,
            legit_data_file=config.legit_data_file,
            ranking_data_file=config.ranking_data_file,

            
        )

        return data_ingestion_config


    def get_data_processing_config(self) -> DataProcessingConfig:
        config = self.config.data_processing

        create_directories([config.root_dir])

        data_processing_config = DataProcessingConfig(
            root_dir=config.root_dir,
            final_data_file = config.final_data_file
            
        )

        return data_processing_config


    
    def get_model_building_config(self) -> ModelBuildingConfig:
        config = self.config.model_building

        create_directories([config.root_dir])

        model_building_config = ModelBuildingConfig(
            root_dir = config.root_dir,
            trained_modl_file = config.trained_modl_file,
            LogisticRegression = self.params.LogisticRegression,
           
            
        )

        return model_building_config



    def get_model_evaluation_config(self) -> ModelEvaluationConfig:

        model_evaluation_config = ModelEvaluationConfig(
            trained_model_path = self.config.model_building.trained_modl_file,
            test_data_path = self.config.data_processing.final_data_file

            
        )

        return model_evaluation_config



    
    