from src.phishingdetection.config.configuration import ConfigurationManager
from src.phishingdetection.components.data_processing import DataProcessing
from src.phishingdetection import logger




STAGE_NAME = "Data Processing stage"

class DataProcessingPipeline:
    def __init__(self):
        pass

    def main(self):
       config = ConfigurationManager()
       data_processing_config = config.get_data_processing_config()
       data_processing = DataProcessing(config=data_processing_config)
       phishing_df, legit_df = data_processing.data_cleaning(config.config.data_ingestion.phishing_data_file, config.config.data_ingestion.legit_data_file)
       data_processing.feature_extraction(phishing_df, legit_df)


if __name__ == '__main__':
    try:
        logger.info(f">>>>>> stage {STAGE_NAME} started <<<<<<")
        obj = DataProcessingPipeline()
        obj.main()
        logger.info(f">>>>>> stage {STAGE_NAME} completed <<<<<<\n\nx==========x")
    except Exception as e:
        logger.exception(e)
        raise e



