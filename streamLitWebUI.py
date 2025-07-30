import streamlit as st
import pandas as pd
import numpy as np
import xgboost as xgb
import subprocess
import re
import os
import tempfile
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder

# === TShark path (adjust if needed)
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# === Interface Fetcher ===
def get_interfaces():
    try:
        result = subprocess.run(
            f'"{TSHARK_PATH}" -D',
            capture_output=True,
            text=True,
            shell=True
        )
        if result.returncode != 0:
            return []
        lines = result.stdout.strip().split("\n")
        return [re.sub(r"^\d+\.\s+", "", line).strip() for line in lines]
    except Exception as e:
        st.error(f"❌ Error fetching interfaces: {str(e)}")
        return []

# === Load XGBoost Model ===
model = xgb.XGBClassifier()
model.load_model("xgb_udp_binary_model_V3.json")

le = LabelEncoder()
le.fit(["BENIGN", "UDP"])

# === Features & Columns ===
group_cols = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"]
features = [
    "Flow Duration", "Fwd Packet Length Mean", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "Average Packet Size",
    "Avg Fwd Segment Size", "Init_Win_bytes_forward"
]

# === Streamlit Setup ===
st.set_page_config(page_title="DDoS Detection SIEM", layout="wide")
st.title("🔐 SIEM: UDP-based DDoS Attacks Detection")
st.caption("Monitor network traffic and detect UDP DDoS attacks using a trained XGBoost model.")

st.sidebar.title("🧭 Navigation")
mode = st.sidebar.radio("Choose Mode", ["📂 Upload Dataset (CSV) File", "📡 Live Network Monitoring"])
if mode == "📡 Live Network Monitoring":
    scan_duration = st.sidebar.slider("🕒 Scan Duration (Seconds)", 5, 60, 15)

# === Mode: Upload CSV ===
if mode == "📂 Upload Dataset (CSV) File":
    with st.expander("📁 Upload Dataset (CSV) File", expanded=True):
        st.markdown("""
        ### 📌 CSV Upload Instructions
        Please ensure your file meets the following criteria:
        - File type: `.csv`
        - Must include the **9 required features** with exact column names:

        ```
        Flow Duration
        Fwd Packet Length Mean
        Max Packet Length
        Packet Length Mean
        Packet Length Std
        Packet Length Variance
        Average Packet Size
        Avg Fwd Segment Size
        Init_Win_bytes_forward
        ```

        - **Case-sensitive**: Column names must match exactly.
        - Missing features will be filled with default values for prediction, but accuracy may be affected.
        """)
        uploaded_file = st.file_uploader("📤 Upload your flow CSV", type="csv")

        if uploaded_file:
            st.info("🔍 Processing and displaying top 1000 rows after prediction...")
            df = pd.read_csv(uploaded_file)
            df.columns = df.columns.str.strip()

            # Remove 'Label' if present
            if "Label" in df.columns:
                df = df.drop(columns=["Label"])

            # Fill missing group columns with "N/A"
            for col in group_cols:
                if col not in df.columns:
                    df[col] = "N/A"

            # Fill missing features with defaults
            defaults = {
                "Flow Duration": 90000,
                "Fwd Packet Length Mean": 370,
                "Max Packet Length": 500,
                "Packet Length Mean": 350,
                "Packet Length Std": 10,
                "Packet Length Variance": 450,
                "Average Packet Size": 360,
                "Avg Fwd Segment Size": 370,
                "Init_Win_bytes_forward": 8192
            }
            for col in features:
                if col not in df.columns:
                    df[col] = defaults[col]

            try:
                # === Prediction and Confidence ===
                predictions = model.predict(df[features])
                probas = model.predict_proba(df[features])
                df["Prediction"] = le.inverse_transform(predictions)
                df["Confidence"] = [proba[pred] for proba, pred in zip(probas, predictions)]
                df["Confidence"] = (df["Confidence"] * 100).round(2).astype(str) + '%'
                udp_count = (df["Prediction"] == "UDP").sum()
                benign_count = (df["Prediction"] == "BENIGN").sum()

                all_other_cols = [c for c in df.columns if c not in group_cols + features + ["Prediction", "Confidence"]]
                ordered_cols = group_cols + ["Prediction", "Confidence"] + features + all_other_cols
                styled_df = df[ordered_cols]


                # --- Styling (same as live mode) ---
                def highlight_group(s):
                    return ['background-color: #28527a; color: white'] * len(s)  # dark blue


                def highlight_features(s):
                    return ['background-color: #b7950b; color: white'] * len(s)  # dark yellow


                def highlight_prediction(s):
                    return [
                        'background-color: #a4161a; color: white' if v == "UDP"
                        else 'background-color: #239b56; color: white' if v == "BENIGN"
                        else 'color: white'
                        for v in s
                    ]


                def highlight_confidence(s):
                    return ['background-color: #ad1457; color: white'] * len(s)  # dark pink


                styled = styled_df.head(1000).style if "Upload" in mode else styled_df.style

                for col in group_cols:
                    styled = styled.apply(highlight_group, subset=[col], axis=0)
                for col in features:
                    styled = styled.apply(highlight_features, subset=[col], axis=0)
                styled = styled.apply(highlight_prediction, subset=["Prediction"], axis=0)
                styled = styled.apply(highlight_confidence, subset=["Confidence"], axis=0)

                st.success("✅ Prediction complete.")

                st.markdown("### 📊 Flow Summary")
                st.download_button("📥 Download CSV with Predictions", styled_df.to_csv(index=False), "csv_results.csv")
                st.dataframe(styled)
                st.markdown("""
                    <div style="margin-bottom: 12px;">
                        <strong style="font-size: 18px;">Legend</strong>
                        <div style="display: flex; flex-direction: row; gap: 14px; margin-top: 8px;">
                            <span style="background-color: #28527a; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                Group Columns<br>(IP/Port/Protocol)
                            </span>
                            <span style="background-color: #b7950b; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                Feature Columns<br>(9 DDoS features)
                            </span>
                            <span style="background-color: #ad1457; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                Confidence<br>(Prediction Confidence)
                            </span>
                            <span style="background-color: #a4161a; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                UDP DDoS Attack
                            </span>
                            <span style="background-color: #239b56; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                BENIGN
                            </span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)



                # === Interface Stats Section ===
                st.markdown("## 📈 Network Flow Statistics")

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("🌐 Total Flows", len(df))
                    st.metric(label="🔴 UDP DDoS Detected", value=udp_count)

                with col2:
                    st.metric("🧠 Unique Source IPs", df["Src IP"].nunique())
                    st.metric(label="🟢 Benign Detected", value=benign_count)

                with col3:
                    avg_duration_ms = df["Flow Duration"].mean() / 1000  # Convert µs to ms
                    st.metric("⏱️ Avg. Flow Duration", f"{avg_duration_ms:,.2f} ms")

                # Top 5 Source IPs
                st.markdown("### 🥇 Top 5 Source IPs")
                top_src = df["Src IP"].value_counts().head(5)
                for ip, count in top_src.items():
                    st.markdown(f"<span style='color: #2ecc71; font-weight: 500;'>🟢 {ip}</span> → {count} flows",
                                unsafe_allow_html=True)
                st.bar_chart(top_src)

                # Protocol Distribution
                st.markdown("### 🧩 Protocol Distribution")
                proto_counts = df["Protocol"].value_counts()
                for proto, count in proto_counts.items():
                    st.markdown(
                        f"<span style='color: #1abc9c; font-weight: 500;'>🔹 Protocol {proto}</span> → {count} flows",
                        unsafe_allow_html=True)

                fig, ax = plt.subplots()
                ax.pie(proto_counts.values, labels=proto_counts.index, autopct="%1.1f%%", startangle=90)
                ax.axis("equal")
                st.pyplot(fig)

            except subprocess.CalledProcessError as e:
                st.error(f"❌ Capture or flow processing failed: {e}")

elif mode == "📡 Live Network Monitoring":
    st.subheader("📡 Live Network Monitoring (TShark + CICFlowMeter)")
    interfaces = get_interfaces()
    if not interfaces:
        st.error("⚠️ No interfaces found. Check TShark installation.")
        st.stop()

    selected_iface = st.selectbox("🖧 Select Network Interface", interfaces)
    selected_protocol = st.selectbox("📶 Protocol Filter", ["udp", "tcp", "All traffic"])
    selected_port = st.text_input("📍 Optional Port Filter", "")

    if st.button("🚨 Start Live Monitoring"):
        with st.spinner("⏳ Capturing traffic..."):
            iface_name = re.search(r'\(([^)]+)\)$', selected_iface)
            iface = iface_name.group(1) if iface_name else selected_iface

            pcap_path = os.path.join(tempfile.gettempdir(), "capture.pcap")
            flow_csv = os.path.join(tempfile.gettempdir(), "flows.csv")

            cap_filter = "" if selected_protocol == "All traffic" else selected_protocol
            if selected_port:
                cap_filter += f" port {selected_port}"

            try:
                subprocess.run([
                    TSHARK_PATH, "-i", iface, "-a", f"duration:{scan_duration}",
                    "-f", cap_filter, "-w", pcap_path
                ], check=True)

                result = subprocess.run([
                    "java",
                    "-Djava.library.path=C:\\Users\\AfqMa\\CICFlowMeter\\jnetpcap\\win\\jnetpcap-1.4.r1425",
                    "-cp", "C:\\Users\\AfqMa\\CICFlowMeter\\build\\libs\\CICFlowMeter-fat-4.0.jar",
                    "cic.cs.unb.ca.ifm.Cmd", "-f", pcap_path, "-c", flow_csv
                ], capture_output=True, text=True, check=True)

                # Extract total packet count
                total_packets = None
                match = re.search(r'Packet stats: Total=(\d+),', result.stdout)
                if match:
                    total_packets = int(match.group(1))
                else:
                    total_packets = "N/A"

                df = pd.read_csv(flow_csv)
                df.columns = df.columns.str.strip()
                if "Label" in df.columns:
                    df = df.drop(columns=["Label"])
                for col in group_cols:
                    if col not in df.columns:
                        df[col] = "N/A"
                for col in features:
                    if col not in df.columns:
                        df[col] = 0

                # === Prediction and Confidence ===
                predictions = model.predict(df[features])
                probas = model.predict_proba(df[features])
                df["Prediction"] = le.inverse_transform(predictions)
                df["Confidence"] = [proba[pred] for proba, pred in zip(probas, predictions)]
                df["Confidence"] = (df["Confidence"] * 100).round(2).astype(str) + '%'
                udp_count = (df["Prediction"] == "UDP").sum()
                benign_count = (df["Prediction"] == "BENIGN").sum()

                all_other_cols = [c for c in df.columns if c not in group_cols + features + ["Prediction", "Confidence"]]
                ordered_cols = group_cols + ["Prediction", "Confidence"] + features + all_other_cols
                styled_df = df[ordered_cols]


                # --- Styling (same as live mode) ---
                def highlight_group(s):
                    return ['background-color: #28527a; color: white'] * len(s)  # dark blue


                def highlight_features(s):
                    return ['background-color: #b7950b; color: white'] * len(s)  # dark yellow


                def highlight_prediction(s):
                    return [
                        'background-color: #a4161a; color: white' if v == "UDP"
                        else 'background-color: #239b56; color: white' if v == "BENIGN"
                        else 'color: white'
                        for v in s
                    ]


                def highlight_confidence(s):
                    return ['background-color: #ad1457; color: white'] * len(s)  # dark pink


                styled = styled_df.head(1000).style if "Upload" in mode else styled_df.style

                for col in group_cols:
                    styled = styled.apply(highlight_group, subset=[col], axis=0)
                for col in features:
                    styled = styled.apply(highlight_features, subset=[col], axis=0)
                styled = styled.apply(highlight_prediction, subset=["Prediction"], axis=0)
                styled = styled.apply(highlight_confidence, subset=["Confidence"], axis=0)

                st.success("✅ Prediction complete.")
                st.markdown("### 📊 Flow Summary")
                st.download_button("📥 Download CSV Result", styled_df.to_csv(index=False), "live_results.csv")
                st.dataframe(styled)

                st.markdown("""
                    <div style="margin-bottom: 12px;">
                        <strong style="font-size: 18px;">Legend</strong>
                        <div style="display: flex; flex-direction: row; gap: 14px; margin-top: 8px;">
                            <span style="background-color: #28527a; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                Group Columns<br>(IP/Port/Protocol)
                            </span>
                            <span style="background-color: #b7950b; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                Feature Columns<br>(9 DDoS features)
                            </span>
                            <span style="background-color: #ad1457; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                Confidence<br>(Prediction Confidence)
                            </span>
                            <span style="background-color: #a4161a; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                UDP DDoS Attack
                            </span>
                            <span style="background-color: #239b56; color: white; padding: 8px 0; border-radius: 7px; min-width: 150px; display: flex; align-items: center; justify-content: center; font-weight: 500; text-align: center;">
                                BENIGN
                            </span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                # === Interface Stats Section ===
                st.markdown("## 📈 Network Flow Statistics")

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("🌐 Total Flows", len(df))
                    st.metric(label="🔴 UDP DDoS Detected", value=udp_count)

                with col2:
                    st.metric("📦 Total Packets", total_packets)
                    st.metric(label="🟢 Benign Detected", value=benign_count)

                with col3:
                    st.metric("🧠 Unique Source IPs", df["Src IP"].nunique())

                with col4:
                    avg_duration_ms = df["Flow Duration"].mean() / 1000  # Convert µs to ms
                    st.metric("⏱️ Avg. Flow Duration", f"{avg_duration_ms:,.2f} ms")

                 # Top 5 Source IPs
                st.markdown("### 🥇 Top 5 Source IPs")
                top_src = df["Src IP"].value_counts().head(5)
                for ip, count in top_src.items():
                    st.markdown(f"<span style='color: #2ecc71; font-weight: 500;'>🟢 {ip}</span> → {count} flows",                                    unsafe_allow_html=True)
                st.bar_chart(top_src)

                # Protocol Distribution
                st.markdown("### 🧩 Protocol Distribution")
                proto_counts = df["Protocol"].value_counts()
                for proto, count in proto_counts.items():
                    st.markdown(f"<span style='color: #1abc9c; font-weight: 500;'>🔹 Protocol {proto}</span> → {count} flows", unsafe_allow_html=True)

                fig, ax = plt.subplots()
                ax.pie(proto_counts.values, labels=proto_counts.index, autopct="%1.1f%%", startangle=90)
                ax.axis("equal")
                st.pyplot(fig)

            except subprocess.CalledProcessError as e:
                st.error(f"❌ Capture or flow processing failed: {e}")
