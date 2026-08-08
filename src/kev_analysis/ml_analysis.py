from __future__ import annotations

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.figure import Figure
from numpy.typing import NDArray
from sklearn.cluster import KMeans  # type: ignore[import-untyped]
from sklearn.decomposition import TruncatedSVD  # type: ignore[import-untyped]
from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]
from sklearn.metrics import silhouette_score  # type: ignore[import-untyped]

from .errors import MlConfigurationError, MlInsufficientDataError
from .models import MlAnalysisResult


def analyze_text_clusters(
    df: pd.DataFrame,
    *,
    candidate_k: tuple[int, ...] = (4, 5, 6, 7, 8),
    random_state: int = 20260806,
) -> MlAnalysisResult:
    """Run reproducible TF-IDF + KMeans exploratory text clustering."""
    required_columns = (
        "cveID",
        "vulnerabilityName",
        "shortDescription",
        "vendor_clean",
        "knownRansomwareCampaignUse",
    )
    _require_columns(df, required_columns)
    candidates = _validate_candidate_k(candidate_k, len(df))
    if not isinstance(random_state, int) or isinstance(random_state, bool):
        raise MlConfigurationError(
            "random_state must be an integer",
            context={"random_state": random_state},
        )

    source = df.loc[:, required_columns].copy(deep=True).reset_index(drop=True)
    if source.empty:
        raise MlInsufficientDataError("text clustering requires at least one record")
    invalid_statuses = sorted(
        set(source["knownRansomwareCampaignUse"].dropna().unique()) - {"Known", "Unknown"}
    )
    if invalid_statuses or source["knownRansomwareCampaignUse"].isna().any():
        raise MlConfigurationError(
            "knownRansomwareCampaignUse must contain only Known or Unknown",
            context={"invalid_values": invalid_statuses},
        )

    analysis_text = (
        source["vulnerabilityName"].fillna("").astype(str).str.strip()
        + " "
        + source["shortDescription"].fillna("").astype(str).str.strip()
    ).str.strip()
    if analysis_text.eq("").any():
        raise MlInsufficientDataError(
            "every record must provide vulnerabilityName or shortDescription",
            context={"empty_rows": analysis_text.index[analysis_text.eq("")].tolist()},
        )

    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
        max_features=5000,
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
    )
    try:
        matrix = vectorizer.fit_transform(analysis_text)
    except ValueError as exc:
        raise MlInsufficientDataError(
            "TF-IDF could not build a usable vocabulary",
            context={"record_count": len(source)},
        ) from exc
    if matrix.shape[1] < 2:
        raise MlInsufficientDataError(
            "TF-IDF requires at least two retained features for clustering",
            context={"feature_count": matrix.shape[1]},
        )

    models: dict[int, KMeans] = {}
    selection_rows: list[dict[str, float | int | bool]] = []
    for k in candidates:
        model = KMeans(n_clusters=k, random_state=random_state, n_init=20)
        labels = model.fit_predict(matrix)
        distinct_clusters = int(np.unique(labels).size)
        if distinct_clusters != k:
            raise MlInsufficientDataError(
                "KMeans could not form every requested cluster",
                context={"k": k, "distinct_clusters": distinct_clusters},
            )
        score = float(silhouette_score(matrix, labels, metric="cosine"))
        models[k] = model
        selection_rows.append(
            {
                "k": k,
                "silhouette_score": score,
                "inertia": float(model.inertia_),
                "selected": False,
            }
        )

    cluster_selection = pd.DataFrame(selection_rows).sort_values("k", kind="mergesort")
    selected_k = int(
        cluster_selection.sort_values(
            ["silhouette_score", "k"],
            ascending=[False, True],
            kind="mergesort",
        ).iloc[0]["k"]
    )
    cluster_selection["selected"] = cluster_selection["k"].eq(selected_k)
    cluster_selection = cluster_selection.reset_index(drop=True)

    selected_model = models[selected_k]
    labels = selected_model.labels_.astype("int64")
    distances = selected_model.transform(matrix)[np.arange(len(source)), labels]
    cluster_results = pd.DataFrame(
        {
            "cveID": source["cveID"].astype(str),
            "cluster_id": labels,
            "distance_to_centroid": distances.astype(float),
            "vulnerabilityName": source["vulnerabilityName"].astype(str),
            "vendor_clean": source["vendor_clean"].astype(str),
            "knownRansomwareCampaignUse": source["knownRansomwareCampaignUse"].astype(str),
        }
    ).sort_values(
        ["cluster_id", "distance_to_centroid", "cveID"],
        ascending=[True, True, True],
        kind="mergesort",
    )
    cluster_results = cluster_results.reset_index(drop=True)

    summary_rows: list[dict[str, float | int | str]] = []
    for cluster_id in range(selected_k):
        cluster = cluster_results[cluster_results["cluster_id"].eq(cluster_id)]
        known_count = int(cluster["knownRansomwareCampaignUse"].eq("Known").sum())
        summary_rows.append(
            {
                "cluster_id": cluster_id,
                "record_count": int(len(cluster)),
                "share": len(cluster) / len(source),
                "known_count": known_count,
                "known_share": known_count / len(cluster),
                "representative_cve": str(cluster.iloc[0]["cveID"]),
            }
        )
    cluster_summary = pd.DataFrame(summary_rows).sort_values("cluster_id", kind="mergesort")
    cluster_summary = cluster_summary.reset_index(drop=True)

    feature_names = vectorizer.get_feature_names_out()
    keyword_rows: list[dict[str, float | int | str]] = []
    keyword_count = min(10, len(feature_names))
    for cluster_id, weights in enumerate(selected_model.cluster_centers_):
        ordered_indices = sorted(
            range(len(feature_names)),
            key=lambda index: (-float(weights[index]), str(feature_names[index])),
        )[:keyword_count]
        for rank, feature_index in enumerate(ordered_indices, start=1):
            keyword_rows.append(
                {
                    "cluster_id": cluster_id,
                    "keyword_rank": rank,
                    "keyword": str(feature_names[feature_index]),
                    "tfidf_weight": float(weights[feature_index]),
                }
            )
    cluster_keywords = pd.DataFrame(keyword_rows).sort_values(
        ["cluster_id", "keyword_rank"], kind="mergesort"
    )
    cluster_keywords = cluster_keywords.reset_index(drop=True)

    svd = TruncatedSVD(n_components=2, random_state=random_state)
    coordinates = svd.fit_transform(matrix)
    figures = {"ml_clusters": _make_cluster_figure(coordinates, labels)}
    return MlAnalysisResult(
        cluster_results=cluster_results,
        cluster_selection=cluster_selection,
        cluster_summary=cluster_summary,
        cluster_keywords=cluster_keywords,
        figures=figures,
    )


def _require_columns(df: pd.DataFrame, columns: tuple[str, ...]) -> None:
    missing = [column for column in columns if column not in df.columns]
    if missing:
        raise MlConfigurationError(
            "text clustering input is missing required columns",
            context={"missing": missing},
        )


def _validate_candidate_k(candidate_k: tuple[int, ...], record_count: int) -> tuple[int, ...]:
    if not isinstance(candidate_k, tuple) or not candidate_k:
        raise MlConfigurationError("candidate_k must be a non-empty tuple of integers")
    if any(not isinstance(k, int) or isinstance(k, bool) for k in candidate_k):
        raise MlConfigurationError(
            "candidate_k must contain integers only",
            context={"candidate_k": candidate_k},
        )
    candidates = tuple(sorted(set(candidate_k)))
    invalid = [k for k in candidates if k < 2 or k >= record_count]
    if invalid:
        raise MlConfigurationError(
            "each candidate k must satisfy 2 <= k < record_count",
            context={"invalid_k": invalid, "record_count": record_count},
        )
    return candidates


def _make_cluster_figure(coordinates: NDArray[np.float64], labels: NDArray[np.int64]) -> Figure:
    figure, axis = plt.subplots(figsize=(9, 6.5))
    scatter = axis.scatter(
        coordinates[:, 0],
        coordinates[:, 1],
        c=labels,
        cmap="tab10",
        alpha=0.72,
        s=24,
        linewidths=0,
    )
    axis.set(
        title="Exploratory TF-IDF + KMeans grouping of vulnerability text",
        xlabel="TruncatedSVD component 1",
        ylabel="TruncatedSVD component 2",
    )
    legend = axis.legend(*scatter.legend_elements(), title="Cluster", loc="best")
    axis.add_artist(legend)
    axis.grid(alpha=0.2)
    figure.tight_layout()
    return figure
