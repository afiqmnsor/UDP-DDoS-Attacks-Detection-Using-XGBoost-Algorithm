import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
import seaborn as sns
import matplotlib.pyplot as plt

# === Load dataset ===
df = pd.read_csv(r"C:\Users\AfqMa\Desktop\FYP\DDoS Datasets\UDP\cleaned_UDP2.csv", low_memory=False)

# ✅ Remove leading/trailing spaces in column names
df.columns = df.columns.str.strip()

features = [
    "Flow Duration", "Fwd Packet Length Mean", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "Average Packet Size",
    "Avg Fwd Segment Size", "Init_Win_bytes_forward"
]

X = df[features]
y = df["Label"]

# === Encode labels ===
le = LabelEncoder()
le.fit(["BENIGN", "UDP"])
y_encoded = le.transform(y)

# === Load trained model ===
model = xgb.XGBClassifier()
model.load_model("xgb_udp_binary_model_report.json")

# === Predict and evaluate ===
y_pred = model.predict(X)

print("✅ Confusion Matrix:")
cm = confusion_matrix(y_encoded, y_pred)
print(cm)

print("\n✅ Classification Report:")
print(classification_report(y_encoded, y_pred, target_names=le.classes_))

# === Plot confusion matrix as heatmap in green color ===
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Greens', xticklabels=le.classes_, yticklabels=le.classes_)
plt.title('Confusion Matrix Heatmap')
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.tight_layout()
plt.show()
