import streamlit as st
import pandas as pd
import joblib
import json
import os # <-- We need this
import streamlit.components.v1 as components 

# --- 0. SET UP FILE PATHS ---
# Get the absolute path to the directory containing this script
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Build absolute paths to all your files
MODEL_PATH = os.path.join(APP_DIR, 'ids_model.joblib')
COLUMNS_PATH = os.path.join(APP_DIR, 'model_columns.json')
PCA_PLOT_PATH = os.path.join(APP_DIR, 'ids_pca_plot.png')

# --- 1. DEFINE THE COLUMN NAMES (CRITICAL FOR UPLOAD) ---
column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack', 'difficulty'
]

# --- 2. LOAD THE MODEL AND MODEL'S COLUMN LIST ---
@st.cache_resource
def load_model_and_cols():
    # Check if files exist using the new absolute paths
    if not os.path.exists(MODEL_PATH) or not os.path.exists(COLUMNS_PATH):
        return None, None
    
    try:
        model = joblib.load(MODEL_PATH)
        with open(COLUMNS_PATH, 'r') as f:
            model_cols = json.load(f)
        return model, model_cols
    except Exception as e:
        st.error(f"Error loading model files: {e}")
        return None, None

model, model_columns = load_model_and_cols()

# --- 3. CREATE THE WEB APP INTERFACE ---
st.title('Advanced IDS Project 🛡️')
st.write('This app analyzes a file of network traffic and classifies each connection.')

# Stop the app if the model files didn't load
if model is None or model_columns is None:
    st.error("🚨 **Model files not found!** 🚨")
    st.write("Please make sure `ids_model.joblib` and `model_columns.json` are in the same folder as `app.py` on GitHub.")
    st.stop() # Stop the app from running further

# Create tabs
tab1, tab2, tab3 = st.tabs(["🚀 Scan a File", "📊 Project Dashboard", "📈 PCA Plot"])


# --- TAB 1: The File Scanner ---
with tab1:
    st.header("Download & Scan a Sample File")
    
    st.subheader("1. Download a Sample File")
    st.write("Click a button to download a sample, then upload it below.")
    
    cols = st.columns(5)
    
    for i in range(1, 11):
        file_name = f"sample_{i}.csv"
        # Build path to the sample file
        sample_file_path = os.path.join(APP_DIR, file_name)
        
        if not os.path.exists(sample_file_path):
             with cols[(i-1) % 5]:
                st.warning(f"Missing {file_name}")
             continue
        
        try:
            with open(sample_file_path, "rb") as f:
                with cols[(i-1) % 5]: 
                    st.download_button(
                        label=f"Sample {i}",
                        data=f,
                        file_name=file_name,
                        mime="text/csv",
                        key=f"btn_{i}"
                    )
        except Exception as e:
             with cols[(i-1) % 5]:
                st.error(f"Error reading {file_name}")

    st.markdown("---") 
    
    st.subheader("2. Upload Your File")
    uploaded_file = st.file_uploader("Upload your CSV or TXT file here", type=["csv", "txt"])
    
    if uploaded_file is not None:
        st.success(f"File '{uploaded_file.name}' uploaded successfully!")
        
        try:
            df_upload = pd.read_csv(uploaded_file, header=None, names=column_names)
            st.write("Scanning file for threats...")
            
            X_upload = df_upload.drop(['attack', 'difficulty'], axis=1, errors='ignore')
            X_upload_processed = pd.get_dummies(X_upload, columns=['protocol_type', 'service', 'flag'])
            X_upload_final = X_upload_processed.reindex(columns=model_columns, fill_value=0)
            
            predictions = model.predict(X_upload_final)
            
            st.header("Scan Results:")
            df_upload['Prediction'] = predictions
            df_upload['Result'] = df_upload['Prediction'].apply(lambda x: '🚨 ATTACK' if x == 1 else '✅ NORMAL')
            
            num_attacks = (df_upload['Prediction'] == 1).sum()
            num_total = len(df_upload)
            
            if num_attacks > 0:
                st.error(f"**Scan Complete: {num_attacks} ATTACK(S) DETECTED** in {num_total} connections.")
            else:
                st.success(f"**Scan Complete: No attacks detected** in {num_total} connections.")
            
            st.subheader(f"Result Breakdown for '{uploaded_file.name}'")
            counts_dict = df_upload['Result'].value_counts().to_dict()
            attack_count = counts_dict.get('🚨 ATTACK', 0)
            normal_count = counts_dict.get('✅ NORMAL', 0)
            chart_data = pd.DataFrame({"🚨 ATTACK": [attack_count], "✅ NORMAL": [normal_count]})
            st.bar_chart(chart_data, color=["#FF4B4B", "#00F2A9"])
            
            st.write("Detailed Report:")
            st.dataframe(df_upload[['attack', 'Result']])

        except Exception as e:
            st.error(f"An error occurred: {e}")
            st.error("Please make sure the file is in the correct NSL-KDD format (43 columns) and not empty.")

# --- TAB 2: THE POWER BI DASHBOARD ---
with tab2:
    st.header("Project Dashboard (Analysis of Test Data)")
    
    # --- 1. REPLACE THIS LINK ---
    power_bi_share_link = "https://app.powerbi.com/groups/me/reports/96676770-d58b-449c-aa35-a289346a7ed6/75ff2635efa1b0d42771?experience=power-bi" 
    
    st.markdown(f"**[Click Here to Open the Full Interactive Dashboard]({power_bi_share_link})**")
    st.info("ⓘ **Note:** This link goes to a secure Power BI report. You may need to log in with a school/organization account to view it.")
    st.markdown("---") 
    
    st.subheader("Dashboard Preview:")
    
    # --- 2. REPLACE THIS FILENAME ---
    # Make sure this filename EXACTLY matches your screenshot file in the same folder
    screenshot_file = "Dashboard.png" # 👈 (I fixed your .png.png typo)
    screenshot_path = os.path.join(APP_DIR, screenshot_file)

    try:
        st.image(screenshot_path, caption="This is a preview of the full dashboard.")
    except FileNotFoundError:
        st.error(f"Error: Screenshot file '{screenshot_file}' not found.")
        st.warning(f"Please add '{screenshot_file}' to your 'nsl-kdd' folder on GitHub.")

# --- TAB 3: THE PCA PLOT ---
with tab3:
    st.header("Why the Model Works (PCA Visualization)")
    
    if not os.path.exists(PCA_PLOT_PATH):
        st.error("🚨 **Image file not found!** 🚨")
        st.write(f"Please make sure `ids_pca_plot.png` is in your 'nsl-kdd' folder on GitHub.")
    else:
        st.image(PCA_PLOT_PATH, caption='PCA Plot: Attacks (red) vs. Normal (blue)')