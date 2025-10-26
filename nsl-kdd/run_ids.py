import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import time  # To time our model training

# --- 1. DEFINE COLUMN NAMES ---
# These are the 41 feature names for the NSL-KDD dataset
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

print("Script started...")

# --- 2. LOAD DATA ---
# We load the training data from the TXT file in the same folder
try:
    df_train = pd.read_csv('KDDTrain+.txt', header=None, names=column_names)
    print("Training data loaded successfully.")
except FileNotFoundError:
    print("Error: 'KDDTrain+.txt' not found.")
    print("Please make sure the file is in the same directory as the script.")
    exit()

# --- 3. PRE-PROCESS DATA ---
print("Pre-processing data...")

# Make it a binary (0 or 1) problem
# 1 = 'attack' (anything not 'normal')
# 0 = 'normal'
df_train['attack_label'] = df_train['attack'].apply(lambda x: 0 if x == 'normal' else 1)

# Drop the original 'attack' and 'difficulty' columns
df_train = df_train.drop(['attack', 'difficulty'], axis=1)

# Convert text columns (categorical) into numbers using One-Hot Encoding
df_processed = pd.get_dummies(df_train, columns=['protocol_type', 'service', 'flag'])

# Separate our features (X) from our target (y)
X = df_processed.drop('attack_label', axis=1)
y = df_processed['attack_label']

print(f"Data shape: {X.shape} features and {y.shape} labels.")

# --- 4. TRAIN THE MODEL ---
# Split data into training and testing sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize the Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

print("Training the Random Forest model... (This may take a minute)")
start_time = time.time()
rf_model.fit(X_train, y_train)
end_time = time.time()
print(f"Model training complete! Time taken: {end_time - start_time:.2f} seconds")

# --- 5. EVALUATE THE MODEL ---
print("Evaluating model...")
y_pred = rf_model.predict(X_test)

print("\n--- Model Evaluation ---")
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")

print("--- Confusion Matrix ---")
print(confusion_matrix(y_test, y_pred))
print("\n")

print("--- Classification Report ---")
print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Attack (1)']))

# --- 6. EXPORT FOR POWER BI ---
print("Saving results to 'ids_results.csv' for Power BI...")
results_df = pd.DataFrame({
    'Actual': y_test,
    'Predicted': y_pred
})
results_df.to_csv('ids_results.csv', index=False)

print("\nScript finished successfully! 🚀")
print("You can now open 'ids_results.csv' in Power BI.")

# --- 7. VISUALIZE THE DATA ---
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
import warnings

print("Generating visualizations...")

# --- Advanced Plot: PCA (Recommended) ---
# We use PCA to shrink all features down to 2 components for plotting
# We only use a "sample" of the data for this to make it run fast
# Let's take 10,000 random samples from our test set

# Suppress a warning from matplotlib about a large number of points
warnings.filterwarnings("ignore", ".*Found rows with one or more missing values.*")

print("Running PCA... this might take a moment.")
pca = PCA(n_components=2) # We want 2 dimensions

# We'll plot a sample from our test data
sample_indices = np.random.choice(X_test.index, size=5000, replace=False)
X_sample = X_test.loc[sample_indices]
y_sample = y_test.loc[sample_indices]

# Run PCA
X_pca = pca.fit_transform(X_sample)
print("PCA complete.")

# Create a new DataFrame for plotting
df_pca = pd.DataFrame(data=X_pca, columns=['PC1', 'PC2'])
df_pca['label'] = y_sample.values

# Separate normal (0) and attack (1) data
normal_data = df_pca[df_pca['label'] == 0]
attack_data = df_pca[df_pca['label'] == 1]

# Create the scatter plot
plt.figure(figsize=(10, 7))
plt.scatter(normal_data['PC1'], normal_data['PC2'], 
            label='Normal (0)', alpha=0.5, s=10, c='blue')
plt.scatter(attack_data['PC1'], attack_data['PC2'], 
            label='Attack (1)', alpha=0.5, s=10, c='red')

plt.title('Attacker vs. Normal Data (Visualized with PCA)')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.legend()
plt.grid(True)

# Save the plot to a file
plt.savefig('ids_pca_plot.png')
print("Plot saved as 'ids_pca_plot.png'")

# Finally, show the plot on your screen
plt.show()

import joblib
import json

# --- 8. SAVE MODEL FOR DEPLOYMENT ---
print("Saving model to file...")

# 1. Save the trained model to 'ids_model.joblib'
joblib.dump(rf_model, 'ids_model.joblib')

# 2. Save the list of columns the model was trained on
model_columns = X.columns.tolist()
with open('model_columns.json', 'w') as f:
    json.dump(model_columns, f)

print("Model and columns saved! Ready for app.")