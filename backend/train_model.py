import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.metrics import confusion_matrix, roc_auc_score


# =============================
# Load Dataset
# =============================

df = pd.read_csv("data/clean_phishing_dataset.csv")
manual_df = pd.read_csv("data/Phishing_Legitimate_full.csv")

df = pd.concat([df, manual_df], ignore_index=True)

print("Columns:", df.columns)

# Convert good/bad to 0/1
df["Label"] = df["Label"].map({"good": 0, "bad": 1})

X = df["URL"]
y = df["Label"]

print("Target Distribution:\n", y.value_counts())


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