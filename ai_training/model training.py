from pathlib import Path
import time
import joblib
import numpy as np
import pandas as pd

from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_PATH = PROJECT_ROOT / "data" / "segmented" / "segmented_multistage_attacks.csv.gz"
MODELS_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_SIZE = 400_000
RANDOM_STATE = 42
FEATURE_COLUMNS = [f"PC{i}" for i in range(1, 27)]
MIN_CLASS_COUNT = 10
FAMILY_CONFIDENCE_THRESHOLD = 0.90


def extract_attack_family(subpattern_series):
    return (
        subpattern_series
        .astype(str)
        .str.strip()
        .str.rsplit("_Pattern_", n=1)
        .str[0]
    )


def clean_features(df):
    for column in FEATURE_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=FEATURE_COLUMNS + ["Subpattern"]).reset_index(drop=True)

    return df


def load_and_sample_data():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found:\n{DATA_PATH}")

    print("[1/7] Loading dataset...")

    df = pd.read_csv(DATA_PATH, compression="gzip", low_memory=False)
    df.columns = df.columns.astype(str).str.strip()

    required_columns = FEATURE_COLUMNS + ["Subpattern"]
    missing_columns = [c for c in required_columns if c not in df.columns]

    if missing_columns:
        raise ValueError(f"Missing columns: {missing_columns}")

    df["Subpattern"] = df["Subpattern"].astype(str).str.strip()
    df = clean_features(df)

    print("Original dataset shape:", df.shape)
    print("[2/7] Creating stratified sample...")

    if len(df) > SAMPLE_SIZE:
        df_sample, _ = train_test_split(
            df,
            train_size=SAMPLE_SIZE,
            random_state=RANDOM_STATE,
            stratify=df["Subpattern"],
        )
    else:
        df_sample = df.copy()

    df_sample = df_sample.reset_index(drop=True)

    class_counts = df_sample["Subpattern"].value_counts()
    valid_classes = class_counts[class_counts >= MIN_CLASS_COUNT].index

    df_sample = (
        df_sample[df_sample["Subpattern"].isin(valid_classes)]
        .reset_index(drop=True)
    )

    df_sample["Attack_Family"] = extract_attack_family(df_sample["Subpattern"])

    print("Remaining subpatterns:", df_sample["Subpattern"].nunique())
    print("Remaining rows:", len(df_sample))
    print("Attack families:", sorted(df_sample["Attack_Family"].unique()))

    distribution = (
        df_sample
        .groupby(["Attack_Family", "Subpattern"])
        .size()
        .reset_index(name="Count")
    )

    distribution["Percentage"] = distribution["Count"] / len(df_sample) * 100

    distribution.to_csv(
        RESULTS_DIR / "hierarchical_improved_distribution.csv",
        index=False,
    )

    return df_sample


def prepare_data(df):
    print("[3/7] Preparing and splitting data...")

    X = df[FEATURE_COLUMNS].copy()
    y_subpattern = df["Subpattern"].copy()
    y_family = df["Attack_Family"].copy()

    all_indices = np.arange(len(df))

    train_validation_indices, test_indices = train_test_split(
        all_indices,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y_subpattern,
    )

    train_indices, validation_indices = train_test_split(
        train_validation_indices,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y_subpattern.iloc[train_validation_indices],
    )

    X_train = X.iloc[train_indices].reset_index(drop=True)
    X_validation = X.iloc[validation_indices].reset_index(drop=True)
    X_test = X.iloc[test_indices].reset_index(drop=True)

    y_train_subpattern = y_subpattern.iloc[train_indices].reset_index(drop=True)
    y_validation_subpattern = y_subpattern.iloc[validation_indices].reset_index(drop=True)
    y_test_subpattern = y_subpattern.iloc[test_indices].reset_index(drop=True)

    y_train_family = y_family.iloc[train_indices].reset_index(drop=True)
    y_validation_family = y_family.iloc[validation_indices].reset_index(drop=True)
    y_test_family = y_family.iloc[test_indices].reset_index(drop=True)

    print("Training rows  :", len(X_train))
    print("Validation rows:", len(X_validation))
    print("Testing rows   :", len(X_test))

    split_summary = pd.DataFrame({
        "Split": ["Training", "Validation", "Testing"],
        "Rows": [len(X_train), len(X_validation), len(X_test)],
    })

    split_summary.to_csv(
        RESULTS_DIR / "hierarchical_improved_split_summary.csv",
        index=False,
    )

    return (
        X_train,
        X_validation,
        X_test,
        y_train_subpattern,
        y_validation_subpattern,
        y_test_subpattern,
        y_train_family,
        y_validation_family,
        y_test_family,
    )


def build_catboost_model(iterations, depth, balanced=False, class_weights=None):
    parameters = {
        "iterations": iterations,
        "depth": depth,
        "learning_rate": 0.05,
        "loss_function": "MultiClass",
        "eval_metric": "MultiClass",
        "random_seed": RANDOM_STATE,
        "verbose": 100,
        "thread_count": 4,
        "allow_writing_files": False,
        "l2_leaf_reg": 5.0,
        "random_strength": 1.0,
        "rsm": 0.90,
        "bootstrap_type": "Bayesian",
        "bagging_temperature": 1.0,
        "border_count": 128,
    }

    if class_weights is not None:
        parameters["class_weights"] = class_weights
    elif balanced:
        parameters["auto_class_weights"] = "Balanced"

    return CatBoostClassifier(**parameters)


def create_internal_split(X_data, y_data, validation_size=0.10):
    class_counts = y_data.value_counts()

    if class_counts.min() < 2:
        return X_data, None, y_data, None

    try:
        X_fit, X_internal_validation, y_fit, y_internal_validation = train_test_split(
            X_data,
            y_data,
            test_size=validation_size,
            random_state=RANDOM_STATE,
            stratify=y_data,
        )

        return X_fit, X_internal_validation, y_fit, y_internal_validation

    except ValueError:
        return X_data, None, y_data, None


def fit_catboost_with_early_stopping(model, X_data, y_data):
    X_fit, X_internal_validation, y_fit, y_internal_validation = create_internal_split(
        X_data,
        y_data,
    )

    if X_internal_validation is None:
        model.fit(X_fit, y_fit)
    else:
        model.fit(
            X_fit,
            y_fit,
            eval_set=(X_internal_validation, y_internal_validation),
            early_stopping_rounds=50,
            use_best_model=True,
        )

    return model


def train_hierarchical_models(X_train, y_train_family, y_train_subpattern):
    print("[4/7] Training family classifier...")

    family_model = build_catboost_model(
        iterations=700,
        depth=10,
        balanced=False,
        class_weights={
            "Benign": 1.0,
            "Bot": 1.2,
            "Infiltration": 2.2,
            "Web Attacks": 2.5,
        },
    )

    family_model = fit_catboost_with_early_stopping(family_model, X_train, y_train_family)

    family_models = {}

    print("[5/7] Training subpattern models inside each family...")

    families = sorted(y_train_family.unique())

    for family in families:
        family_mask = y_train_family == family

        X_family = X_train.loc[family_mask].reset_index(drop=True)
        y_family_subpattern = y_train_subpattern.loc[family_mask].reset_index(drop=True)

        number_of_classes = y_family_subpattern.nunique()

        print(
            f"Family: {family} | "
            f"rows: {len(X_family)} | "
            f"subpatterns: {number_of_classes}"
        )

        if number_of_classes == 1:
            family_models[family] = {
                "type": "constant",
                "value": y_family_subpattern.iloc[0],
            }
            continue

        use_balancing = family in ["Bot", "Web Attacks"]
        subpattern_class_weights = None

        if family == "Infiltration":
            counts = y_family_subpattern.value_counts()
            max_count = counts.max()

            subpattern_class_weights = {}

            for class_name, count in counts.items():
                weight = min((max_count / count) ** 0.5, 3.0)
                subpattern_class_weights[class_name] = weight

        if family == "Benign":
            model_iterations, model_depth = 600, 9
        elif family == "Bot":
            model_iterations, model_depth = 700, 10
        elif family == "Infiltration":
            model_iterations, model_depth = 900, 10
        else:
            model_iterations, model_depth = 700, 8

        subpattern_model = build_catboost_model(
            iterations=model_iterations,
            depth=model_depth,
            balanced=use_balancing,
            class_weights=subpattern_class_weights,
        )

        subpattern_model = fit_catboost_with_early_stopping(
            subpattern_model,
            X_family,
            y_family_subpattern,
        )

        family_models[family] = {
            "type": "model",
            "model": subpattern_model,
        }

    return family_model, family_models


def predict_subpattern_with_probability(family_information, X_data):
    if family_information["type"] == "constant":
        predictions = np.full(len(X_data), family_information["value"], dtype=object)
        probabilities = np.ones(len(X_data), dtype=float)

        return predictions, probabilities

    model = family_information["model"]

    probabilities_matrix = model.predict_proba(X_data)
    classes = np.asarray(model.classes_)
    best_indices = np.argmax(probabilities_matrix, axis=1)

    predictions = classes[best_indices]
    best_probabilities = probabilities_matrix[np.arange(len(X_data)), best_indices]

    return predictions.astype(object), best_probabilities


def hierarchical_predict(family_model, family_models, X_data):
    family_probability_matrix = family_model.predict_proba(X_data)
    family_classes = np.asarray(family_model.classes_)

    sorted_family_indices = np.argsort(family_probability_matrix, axis=1)[:, ::-1]
    top_family_indices = sorted_family_indices[:, 0]
    second_family_indices = sorted_family_indices[:, 1]

    top_family_probabilities = family_probability_matrix[
        np.arange(len(X_data)),
        top_family_indices,
    ]

    predicted_families = family_classes[top_family_indices].astype(object)

    final_subpattern_predictions = np.empty(len(X_data), dtype=object)
    final_subpattern_probabilities = np.zeros(len(X_data), dtype=float)
    final_joint_scores = np.zeros(len(X_data), dtype=float)

    low_confidence_mask = top_family_probabilities < FAMILY_CONFIDENCE_THRESHOLD

    # First-choice family prediction for every row
    for family in np.unique(predicted_families):
        positions = np.where(predicted_families == family)[0]
        family_information = family_models[family]

        subpattern_predictions, subpattern_probabilities = predict_subpattern_with_probability(
            family_information,
            X_data.iloc[positions],
        )

        family_position_indices = top_family_indices[positions]
        family_probabilities = family_probability_matrix[positions, family_position_indices]
        joint_scores = family_probabilities * subpattern_probabilities

        final_subpattern_predictions[positions] = subpattern_predictions
        final_subpattern_probabilities[positions] = subpattern_probabilities
        final_joint_scores[positions] = joint_scores

    # For low-confidence rows, compare against the second-best family
    low_confidence_positions = np.where(low_confidence_mask)[0]

    if len(low_confidence_positions) > 0:
        second_predicted_families = family_classes[
            second_family_indices[low_confidence_positions]
        ]

        for second_family in np.unique(second_predicted_families):
            family_positions_inside_low = np.where(
                second_predicted_families == second_family
            )[0]

            original_positions = low_confidence_positions[family_positions_inside_low]
            family_information = family_models[second_family]

            second_subpattern_predictions, second_subpattern_probabilities = (
                predict_subpattern_with_probability(
                    family_information,
                    X_data.iloc[original_positions],
                )
            )

            second_family_column_indices = second_family_indices[original_positions]
            second_family_probabilities = family_probability_matrix[
                original_positions,
                second_family_column_indices,
            ]

            second_joint_scores = second_family_probabilities * second_subpattern_probabilities

            replace_mask = second_joint_scores > final_joint_scores[original_positions]
            positions_to_replace = original_positions[replace_mask]

            if len(positions_to_replace) > 0:
                final_subpattern_predictions[positions_to_replace] = (
                    second_subpattern_predictions[replace_mask]
                )
                final_subpattern_probabilities[positions_to_replace] = (
                    second_subpattern_probabilities[replace_mask]
                )
                predicted_families[positions_to_replace] = second_family
                final_joint_scores[positions_to_replace] = second_joint_scores[replace_mask]

    return (
        predicted_families,
        final_subpattern_predictions,
        top_family_probabilities,
        final_subpattern_probabilities,
        final_joint_scores,
        low_confidence_mask,
    )


def evaluate_model(
    family_model,
    family_models,
    X_data,
    y_true_family,
    y_true_subpattern,
    split_name,
):
    (
        predicted_family,
        predicted_subpattern,
        family_confidence,
        subpattern_confidence,
        final_joint_score,
        low_confidence_mask,
    ) = hierarchical_predict(family_model, family_models, X_data)

    family_accuracy = accuracy_score(y_true_family, predicted_family)
    subpattern_accuracy = accuracy_score(y_true_subpattern, predicted_subpattern)

    precision_macro = precision_score(
        y_true_subpattern, predicted_subpattern, average="macro", zero_division=0
    )
    recall_macro = recall_score(
        y_true_subpattern, predicted_subpattern, average="macro", zero_division=0
    )
    f1_macro = f1_score(
        y_true_subpattern, predicted_subpattern, average="macro", zero_division=0
    )

    precision_weighted = precision_score(
        y_true_subpattern, predicted_subpattern, average="weighted", zero_division=0
    )
    recall_weighted = recall_score(
        y_true_subpattern, predicted_subpattern, average="weighted", zero_division=0
    )
    f1_weighted = f1_score(
        y_true_subpattern, predicted_subpattern, average="weighted", zero_division=0
    )

    low_confidence_percentage = low_confidence_mask.mean() * 100

    print(f"\n{split_name} results:")
    print(f"Family Accuracy       : {family_accuracy:.4f}")
    print(f"Subpattern Accuracy   : {subpattern_accuracy:.4f}")
    print(f"Precision Macro       : {precision_macro:.4f}")
    print(f"Recall Macro          : {recall_macro:.4f}")
    print(f"F1 Macro              : {f1_macro:.4f}")
    print(f"Precision Weighted    : {precision_weighted:.4f}")
    print(f"Recall Weighted       : {recall_weighted:.4f}")
    print(f"F1 Weighted           : {f1_weighted:.4f}")
    print(f"Low-confidence rows   : {low_confidence_percentage:.2f}%")

    report = classification_report(
        y_true_subpattern,
        predicted_subpattern,
        output_dict=True,
        zero_division=0,
    )
    report_df = pd.DataFrame(report).transpose()

    report_df.to_csv(
        RESULTS_DIR / f"{split_name.lower()}_hierarchical_improved_report.csv"
    )

    labels = sorted(y_true_subpattern.unique())
    matrix = confusion_matrix(y_true_subpattern, predicted_subpattern, labels=labels)
    matrix_df = pd.DataFrame(matrix, index=labels, columns=labels)

    matrix_df.to_csv(
        RESULTS_DIR / f"{split_name.lower()}_hierarchical_improved_confusion_matrix.csv"
    )

    predictions_df = pd.DataFrame({
        "Actual_Family": y_true_family.to_numpy(),
        "Predicted_Family": predicted_family,
        "Actual_Subpattern": y_true_subpattern.to_numpy(),
        "Predicted_Subpattern": predicted_subpattern,
        "Family_Confidence": family_confidence,
        "Subpattern_Confidence": subpattern_confidence,
        "Final_Joint_Score": final_joint_score,
        "Low_Confidence": low_confidence_mask,
        "Correct_Family": y_true_family.to_numpy() == predicted_family,
        "Correct_Subpattern": y_true_subpattern.to_numpy() == predicted_subpattern,
    })

    predictions_df.to_csv(
        RESULTS_DIR / f"{split_name.lower()}_hierarchical_improved_predictions.csv",
        index=False,
    )

    return {
        "Split": split_name,
        "Family_Accuracy": family_accuracy,
        "Subpattern_Accuracy": subpattern_accuracy,
        "Precision_Macro": precision_macro,
        "Recall_Macro": recall_macro,
        "F1_Macro": f1_macro,
        "Precision_Weighted": precision_weighted,
        "Recall_Weighted": recall_weighted,
        "F1_Weighted": f1_weighted,
        "Low_Confidence_Percentage": low_confidence_percentage,
    }


def main():
    df = load_and_sample_data()

    (
        X_train,
        X_validation,
        X_test,
        y_train_subpattern,
        y_validation_subpattern,
        y_test_subpattern,
        y_train_family,
        y_validation_family,
        y_test_family,
    ) = prepare_data(df)

    print("[6/7] Training improved hierarchical classifier...")

    start_time = time.time()

    family_model, family_models = train_hierarchical_models(
        X_train,
        y_train_family,
        y_train_subpattern,
    )

    training_seconds = time.time() - start_time

    print(f"Training completed in {training_seconds / 60:.2f} minutes.")

    saved_model = {
        "family_model": family_model,
        "family_models": family_models,
        "feature_columns": FEATURE_COLUMNS,
        "confidence_threshold": FAMILY_CONFIDENCE_THRESHOLD,
        "sample_size": SAMPLE_SIZE,
        "random_state": RANDOM_STATE,
    }

    model_path = MODELS_DIR / "hierarchical_subpattern_classifier_improved.joblib"
    joblib.dump(saved_model, model_path)

    print("Model saved:", model_path)
    print("[7/7] Evaluating models...")

    validation_metrics = evaluate_model(
        family_model,
        family_models,
        X_validation,
        y_validation_family,
        y_validation_subpattern,
        "Validation",
    )

    test_metrics = evaluate_model(
        family_model,
        family_models,
        X_test,
        y_test_family,
        y_test_subpattern,
        "Test",
    )

    metrics_df = pd.DataFrame([validation_metrics, test_metrics])
    metrics_df["Training_Seconds"] = training_seconds

    metrics_path = RESULTS_DIR / "hierarchical_improved_metrics.csv"
    metrics_df.to_csv(metrics_path, index=False)

    print("\nFinal metrics:")
    print(metrics_df.to_string(index=False))
    print("Metrics saved:", metrics_path)


if __name__ == "__main__":
    main()
