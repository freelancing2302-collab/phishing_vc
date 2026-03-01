import joblib
import numpy as np

model = joblib.load("model/meta_model.pkl")

def predict_url(features):
    features = np.array(features).reshape(1, -1)
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0][1]

    return prediction, probability
