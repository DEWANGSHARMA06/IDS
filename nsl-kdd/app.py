import streamlit as st
import pandas as pd
import joblib
import json
import os # Used to check if files exist
import streamlit.components.v1 as components 

# --- 1. DEFINE THE COLUMN NAMES (CRITICAL FOR UPLOAD) ---
# This list MUST match the format of your sample files
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
# Use @st.cache_resource to load this only once
@st.cache_resource
def load_model_and_cols():
    # Check if files exist first
    if not os.path.exists('ids_model.joblib') or not os.path.exists('model_columns.json'):
        return None, None
    
    try:
        model = joblib.load('ids_model.joblib')
        with open('model_columns.json', 'r') as f:
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
    st.write("Please make sure `ids_model.joblib` and `model_columns.json` are in the same folder as `app.py`.")
    st.stop() # Stop the app from running further

# Create tabs
tab1, tab2, tab3 = st.tabs(["🚀 Scan a File", "📊 Project Dashboard", "📈 PCA Plot"])


# --- TAB 1: The File Scanner ---
with tab1:
    st.header("Download & Scan a Sample File")
    
    st.subheader("1. Download a Sample File")
    st.write("Click a button to download a sample, then upload it below.")
    
    # Create 5 columns to hold the 10 buttons neatly
    cols = st.columns(5)
    
    for i in range(1, 11):
        file_name = f"sample_{i}.csv"
        
        # Check if the sample file exists in the folder
        if not os.path.exists(file_name):
             with cols[(i-1) % 5]:
                st.warning(f"Missing {file_name}")
             continue # Skip to the next loop iteration
        
        # If file exists, create the download button
        try:
            with open(file_name, "rb") as f:
                with cols[(i-1) % 5]: 
                    st.download_button(
                        label=f"Sample {i}",
                        data=f,
                        file_name=file_name,
                        mime="text/csv",
                        key=f"btn_{i}" # Add a unique key for each button
                    )
        except Exception as e:
             with cols[(i-1) % 5]:
                st.error(f"Error reading {file_name}")

    st.markdown("---") # Add a separator
    
    # --- Create the file uploader ---
    st.subheader("2. Upload Your File")
    uploaded_file = st.file_uploader("Upload your CSV or TXT file here", type=["csv", "txt"])
    
    if uploaded_file is not None:
        # File is uploaded
        st.success(f"File '{uploaded_file.name}' uploaded successfully!")
        
        try:
            # Read the uploaded file into a DataFrame
            df_upload = pd.read_csv(uploaded_file, header=None, names=column_names)

            # --- Start Processing ---
            st.write("Scanning file for threats...")
            
            # Drop columns the model wasn't trained on
            X_upload = df_upload.drop(['attack', 'difficulty'], axis=1, errors='ignore')
            
            # One-hot encode the categorical features
            X_upload_processed = pd.get_dummies(X_upload, columns=['protocol_type', 'service', 'flag'])
            
            # Align columns with the model's training data (CRITICAL)
            X_upload_final = X_upload_processed.reindex(columns=model_columns, fill_value=0)
            
            # --- Make Predictions ---
            predictions = model.predict(X_upload_final)
            
            # --- Show the Results ---
            st.header("Scan Results:")
            
            df_upload['Prediction'] = predictions
            df_upload['Result'] = df_upload['Prediction'].apply(lambda x: '🚨 ATTACK' if x == 1 else '✅ NORMAL')
            
            # Show summary
            num_attacks = (df_upload['Prediction'] == 1).sum()
            num_total = len(df_upload)
            
            if num_attacks > 0:
                st.error(f"**Scan Complete: {num_attacks} ATTACK(S) DETECTED** in {num_total} connections.")
            else:
                st.success(f"**Scan Complete: No attacks detected** in {num_total} connections.")
            
            # --- !! CORRECTED GRAPH CODE !! ---
            st.subheader(f"Result Breakdown for '{uploaded_file.name}'")
            
            # Get the counts for each category
            counts_dict = df_upload['Result'].value_counts().to_dict()
            
            # Get counts, defaulting to 0 if a category is missing
            attack_count = counts_dict.get('🚨 ATTACK', 0)
            normal_count = counts_dict.get('✅ NORMAL', 0)

            # Create a new DataFrame in the correct shape for coloring
            # This DataFrame will have TWO columns, even if one is 0
            chart_data = pd.DataFrame({
                "🚨 ATTACK": [attack_count],
                "✅ NORMAL": [normal_count]
            })
            
            # Now, plot this DataFrame and apply the colors
            # The 2 colors will match the 2 columns
            st.bar_chart(chart_data, color=["#FF4B4B", "#00F2A9"])
            
            # --- END OF CORRECTION ---
            
            # Show the detailed table
            st.write("Detailed Report:")
            st.dataframe(df_upload[['attack', 'Result']])

        except Exception as e:
            st.error(f"An error occurred: {e}")
            st.error("Please make sure the file is in the correct NSL-KDD format (43 columns) and not empty.")

# --- TAB 2: THE POWER BI DASHBOARD ---
with tab2:
    st.header("Project Dashboard (Analysis of Test Data)")
    
    # --- 1. YOUR POWER BI SHARE LINK ---
    # This link is correct. Keep it as-is.
    power_bi_share_link = "YOUR_POWER_BI_SHARE_LINK_HERE" # 👈 (You already did this)
    
    
    st.markdown(f"**[Click Here to Open the Full Interactive Dashboard]({power_bi_share_link})**")
    
    st.info("ⓘ **Note:** This link goes to a secure Power BI report. You may need to log in with a school/organization account to view it.")
    st.markdown("---") # Separator
    
    st.subheader("Dashboard Preview:")
    
    # --- 2. THE LOCAL SCREENSHOT (THE FIX) ---
    # Put your screenshot file (e.g., "dashboard.png") in the same folder as your app.py
    # and write its name here.
    
    screenshot_file = "Dashboard.png.png" # 👈 **REPLACE THIS FILENAME**

    try:
        st.image(screenshot_file, caption="This is a preview of the full dashboard.")
    except FileNotFoundError:
        st.error(f"Error: Screenshot file '{screenshot_file}' not found.")
        st.warning("Please add your dashboard screenshot to the app folder.")

# --- TAB 3: THE PCA PLOT ---
with tab3:
    st.header("Why the Model Works (PCA Visualization)")
    
    # Check if the PCA plot file exists
    if not os.path.exists('ids_pca_plot.png'):
        st.error("🚨 **Image file not found!** 🚨")
        st.write("Please make sure `ids_pca_plot.png` is in the same folder as `app.py`.")
    else:
        st.image('ids_pca_plot.png', caption='PCA Plot: Attacks (red) vs. Normal (blue)')