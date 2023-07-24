from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DataIngestionConfig:
    root_dir: Path
    source_URL_phishing: str
    source_URL_legit: str
    source_URL_ranking: str
    phishing_data_file: Path
    legit_data_file: Path
    ranking_data_file: Path



@dataclass(frozen=True)
class DataProcessingConfig:
    root_dir: Path
    final_data_file: Path



@dataclass(frozen=True)
class ModelBuildingConfig:
    root_dir: Path
    trained_modl_file: Path
    LogisticRegression: dict




@dataclass(frozen=True)
class ModelEvaluationConfig:
    trained_model_path: Path
    test_data_path: Path


