from src.phishingdetection.config.configuration import ConfigurationManager
from src.phishingdetection.components.model_evaluation import ModelEvaluation
from src.phishingdetection import logger


STAGE_NAME = "Model Evaluation stage"

class ModelEvaluationPipeline:
    def __init__(self):
        pass

    def main(self):
        config = ConfigurationManager()
        evaluation_config = config.get_model_evaluation_config()
        evaluation = ModelEvaluation(evaluation_config)
        evaluation.evaluate(evaluation_config.trained_model_path, evaluation_config.test_data_path)
       


if __name__ == '__main__':
    try:
        logger.info(f">>>>>> stage {STAGE_NAME} started <<<<<<")
        obj = ModelEvaluationPipeline()
        obj.main()
        logger.info(f">>>>>> stage {STAGE_NAME} completed <<<<<<\n\nx==========x")
    except Exception as e:
        logger.exception(e)
        raise e



