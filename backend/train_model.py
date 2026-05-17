import pandas as pd
import joblib
import os
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.metrics import confusion_matrix, roc_auc_score


# =============================
# Load Dataset
# =============================

# Load first dataset
df = pd.read_csv("data/clean_phishing_dataset.csv")
print("Dataset 1 columns:", df.columns.tolist())
print("Dataset 1 shape:", df.shape)

# Check if it has URL and Label columns
if 'URL' in df.columns and 'Label' in df.columns:
    print("✅ Dataset 1 is valid (has URL and Label)")
    df = df[['URL', 'Label']].rename(columns={'Label': 'label_final'})
else:
    print("❌ Dataset 1 missing URL or Label, skipping")
    df = None

# Load second dataset
manual_df = pd.read_csv("data/Phishing_Legitimate_full.csv")
print("\nDataset 2 columns:", manual_df.columns.tolist())
print("Dataset 2 shape:", manual_df.shape)

# Check if it has URL column
if 'URL' in manual_df.columns:
    print("✅ Dataset 2 is valid (has URL)")
    if 'CLASS_LABEL' in manual_df.columns:
        manual_df = manual_df[['URL', 'CLASS_LABEL']].rename(columns={'CLASS_LABEL': 'label_final'})
    elif 'Label' in manual_df.columns:
        manual_df = manual_df[['URL', 'Label']].rename(columns={'Label': 'label_final'})
    else:
        print("❌ Dataset 2 has no label column, skipping")
        manual_df = None
else:
    print("❌ Dataset 2 has no URL column (feature-extracted data), skipping")
    manual_df = None

# Combine valid datasets
if df is not None and manual_df is not None:
    df = pd.concat([df, manual_df], ignore_index=True)
    print("\n✅ Using both datasets")
elif df is not None:
    print("\n⚠️ Using only Dataset 1 (Dataset 2 is feature-extracted)")
else:
    raise ValueError("No valid datasets found!")

print(f"Combined dataset shape: {df.shape}")
print("Label value counts before cleaning:")
print(df['label_final'].value_counts(dropna=False))

# Remove rows with NaN in URL or label
df = df.dropna(subset=['URL', 'label_final'])
print(f"\nAfter removing NaN: {len(df)} samples")

# Convert labels to numeric (0=legitimate, 1=phishing)
y_raw = df['label_final'].astype(str).str.strip()
print(f"Unique label values: {y_raw.unique()}")

# Create mapping for all possible values
mapping = {
    "0": 0, "good": 0, "legitimate": 0,
    "1": 1, "-1": 1, "bad": 1, "phishing": 1
}

y = y_raw.map(mapping)

# Show any unmapped values
unmapped = y_raw[y.isna()].unique()
if len(unmapped) > 0:
    print(f"Unmapped values: {unmapped}")
    # Fallback: treat anything with -1 or non-zero as phishing
    for val in unmapped:
        try:
            num_val = float(val)
            mapping[val] = 1 if num_val != 0 else 0
        except:
            mapping[val] = 0  # Default to legitimate if can't parse
    
    y = y_raw.map(mapping)

# Remove any remaining NaN
valid_idx = ~y.isna()
y = y[valid_idx]
X = df.loc[valid_idx, 'URL'].reset_index(drop=True)
y = y.astype(int).reset_index(drop=True)

print(f"\n✅ Final dataset - Total samples: {len(X)}")
print("Target Distribution:")
print(y.value_counts())


# =============================
# Train-Test Split (Stratified)
# =============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# =============================
# TF-IDF Vectorization
# =============================

vectorizer = TfidfVectorizer(
    analyzer='char',
    ngram_range=(3, 5),
    min_df=5,
    max_df=0.95,
    sublinear_tf=True
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)


# =============================
# Train Model (Random Forest)
# =============================

model = RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("\nTraining Model...")
model.fit(X_train_vec, y_train)
print("Training Completed!")


# =============================
# Evaluation
# =============================

y_pred = model.predict(X_test_vec)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nROC-AUC Score:")
print(roc_auc_score(y_test, model.predict_proba(X_test_vec)[:,1]))

print("\nClass Order:", model.classes_)


# =============================
# Save Model + Vectorizer
# =============================

os.makedirs("model", exist_ok=True)

joblib.dump(model, "model/phishing_model.pkl")
joblib.dump(vectorizer, "model/vectorizer.pkl")

print("\nModel and Vectorizer saved successfully!")