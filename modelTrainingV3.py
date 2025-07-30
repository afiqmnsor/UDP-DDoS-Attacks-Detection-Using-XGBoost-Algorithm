import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
from imblearn.over_sampling import SMOTE

# === Load dataset ===
df = pd.read_csv(r"C:\Users\AfqMa\Desktop\FYP\DDoS Datasets\UDP\cleaned_UDP.csv", low_memory=False)
df.columns = df.columns.str.strip()

# === Define features and label ===
features = [
    "Flow Duration", "Fwd Packet Length Mean", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "Average Packet Size",
    "Avg Fwd Segment Size", "Init_Win_bytes_forward"
]
X = df[features]
y = df["Label"]

# === Encode target ===
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# === Handle imbalance using SMOTE ===
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y_encoded)

# === Train/Test split ===
X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)

# === Train model ===
model = xgb.XGBClassifier(
    objective='binary:logistic',
    eval_metric='logloss',
    use_label_encoder=False
)
model.fit(X_train, y_train)

# === Predict and Evaluate ===
y_pred = model.predict(X_test)

# === Confusion Matrix (Text) ===
print("✅ Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# === Confusion Matrix (Graph) ===
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=le.classes_, yticklabels=le.classes_)
plt.title("Confusion Matrix")
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.tight_layout()
plt.savefig("confusion_matrix.png")
plt.show()

# === Classification Report (Text) ===
print("\n✅ Classification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# === Save model ===
model.save_model("xgb_udp_binary_model_report.json")
print("✅ Model saved to xgb_udp_binary_model_report.json")
