from src.phishingdetection.config.configuration import ConfigurationManager
from src.phishingdetection.components.model_building import ModelBuilding
from src.phishingdetection import logger


STAGE_NAME = "Model Building stage"

class ModelBuildingPipeline:
    def __init__(self):
        pass

    def main(self):
        config = ConfigurationManager()
        model_building_config = config.get_model_building_config()
        model_building = ModelBuilding(config=model_building_config)
        model_building.train_model(config.config.data_processing.final_data_file)


if __name__ == '__main__':
    try:
        logger.info(f">>>>>> stage {STAGE_NAME} started <<<<<<")
        obj = ModelBuildingPipeline()
        obj.main()
        logger.info(f">>>>>> stage {STAGE_NAME} completed <<<<<<\n\nx==========x")
    except Exception as e:
        logger.exception(e)
        raise e



