import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib

# Helper function to check if an IP is local/private
def is_local_ip(ip):
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        return False
    except:
        return False

# Helper function to extract the first octet of an IP
def get_first_octet(ip):
    try:
        return int(ip.split('.')[0])
    except:
        return 0

# Step 1: Load the dataset
df = pd.read_csv('access_logs.csv')
print("Original Dataset Shape:", df.shape)
print("Original Label Distribution:\n", df['Label'].value_counts())
print("Missing Values:\n", df.isnull().sum())

# Step 2: Relabel potential mislabeled entries - using more specific patterns to avoid overfitting
xss_pattern = '<script>.*</script>'
command_injection_pattern = ';.*\\&|;.*\\|'
lfi_pattern = '\.\./\.\./'

# Only relabel if multiple indicators are present or if it's a clear attack pattern
def is_likely_attack(path):
    suspicious_count = 0
    if '<script>' in path.lower(): suspicious_count += 1
    if ';' in path and ('&' in path or '|' in path): suspicious_count += 1
    if '../' in path and path.count('../') > 1: suspicious_count += 1
    if '%00' in path: suspicious_count += 1  # Null byte injection
    if 'union select' in path.lower(): suspicious_count += 1  # SQL injection
    return suspicious_count >= 1

# More conservative relabeling
df.loc[(df['Path'].str.contains(xss_pattern, case=False, na=False)) & (df['Label'] == 0), 'Label'] = 1
df.loc[(df['Path'].str.contains(command_injection_pattern, na=False)) & (df['Label'] == 0), 'Label'] = 1
df.loc[(df['Path'].str.contains(lfi_pattern, na=False)) & (df['Label'] == 0), 'Label'] = 1
df.loc[df['Path'].apply(is_likely_attack) & (df['Label'] == 0), 'Label'] = 1

print("\nLabel Distribution After Relabeling:\n", df['Label'].value_counts())

# Step 3: Identify common IPs (top 10% most frequent)
ip_counts = df['IP'].value_counts()
common_ip_threshold = ip_counts.quantile(0.9)  # Top 10% most frequent IPs
common_ips = ip_counts[ip_counts >= common_ip_threshold].index.tolist()

# Save common IPs for use in prediction script
joblib.dump(common_ips, 'common_ips.pkl')

# Step 4: Augment the dataset with synthetic examples - more balanced approach
num_malicious_per_type = 300  # Reduced to prevent overwhelming the dataset
num_white_per_type = 5000    # Increased to better balance classes

# Synthetic Malicious Examples (XSS, Command Injection, LFI)
xss_entries = pd.DataFrame({
    'IP': ['203.0.113.' + str(i % 256) for i in range(num_malicious_per_type)],
    'Timestamp': ['[2023-03-26:23:11:20]'] * num_malicious_per_type,
    'Method': ['GET'] * (num_malicious_per_type // 2) + ['POST'] * (num_malicious_per_type // 2),
    'Path': [f"/search?query=<script>alert('xss{i}')</script>" for i in range(num_malicious_per_type)],
    'Protocol': ['HTTP/1.1'] * num_malicious_per_type,
    'Status': [200] * num_malicious_per_type,
    'Size': [np.random.randint(1000, 1500) for _ in range(num_malicious_per_type)],
    'Referer': ['-'] * num_malicious_per_type,
    'User-Agent': ['Mozilla/5.0'] * num_malicious_per_type,
    'Comment': ['xss'] * num_malicious_per_type,
    'Label': [1] * num_malicious_per_type
})

command_injection_entries = pd.DataFrame({
    'IP': ['198.51.100.' + str(i % 256) for i in range(num_malicious_per_type)],
    'Timestamp': ['[2023-03-26:23:11:20]'] * num_malicious_per_type,
    'Method': ['GET'] * (num_malicious_per_type // 2) + ['POST'] * (num_malicious_per_type // 2),
    'Path': [f"/execute?cmd=;cat%20/etc/passwd{i}" for i in range(num_malicious_per_type)],
    'Protocol': ['HTTP/1.1'] * num_malicious_per_type,
    'Status': [500] * num_malicious_per_type,
    'Size': [np.random.randint(200, 500) for _ in range(num_malicious_per_type)],
    'Referer': ['-'] * num_malicious_per_type,
    'User-Agent': ['Mozilla/5.0'] * num_malicious_per_type,
    'Comment': ['command injection'] * num_malicious_per_type,
    'Label': [1] * num_malicious_per_type
})

lfi_entries = pd.DataFrame({
    'IP': ['192.0.2.' + str(i % 256) for i in range(num_malicious_per_type)],
    'Timestamp': ['[2023-03-26:23:11:20]'] * num_malicious_per_type,
    'Method': ['GET'] * (num_malicious_per_type // 2) + ['POST'] * (num_malicious_per_type // 2),
    'Path': [f"/view?file=../../../etc/passwd{i}" for i in range(num_malicious_per_type)],
    'Protocol': ['HTTP/1.1'] * num_malicious_per_type,
    'Status': [403] * num_malicious_per_type,
    'Size': [np.random.randint(300, 600) for _ in range(num_malicious_per_type)],
    'Referer': ['-'] * num_malicious_per_type,
    'User-Agent': ['Mozilla/5.0'] * num_malicious_per_type,
    'Comment': ['lfi'] * num_malicious_per_type,
    'Label': [1] * num_malicious_per_type
})

# Synthetic White Traffic Examples (Static Resources, Nested Static Resources, API-Like Paths)
# Split static resources into those with and without referer
white_traffic_static_with_referer = pd.DataFrame({
    'IP': ['192.168.1.' + str(i % 256) for i in range(num_white_per_type // 2)],
    'Timestamp': ['[2023-03-26:23:11:20]'] * (num_white_per_type // 2),
    'Method': ['GET'] * (num_white_per_type // 4) + ['POST'] * (num_white_per_type // 8) + ['PUT'] * (num_white_per_type // 8),
    'Path': [f"/static/resource{i}.{ext}" for i, ext in enumerate(['jpg', 'png', 'css', 'js'] * (num_white_per_type // 8))],
    'Protocol': ['HTTP/1.1'] * (num_white_per_type // 2),
    'Status': [200] * (num_white_per_type // 2),
    'Size': [np.random.randint(5000, 100000) for _ in range(num_white_per_type // 2)],  # Larger sizes for static resources
    'Referer': ['http://example.com/page'] * (num_white_per_type // 2),
    'User-Agent': ['Mozilla/5.0'] * (num_white_per_type // 2),
    'Comment': ['white traffic'] * (num_white_per_type // 2),
    'Label': [0] * (num_white_per_type // 2)
})

white_traffic_static_no_referer = pd.DataFrame({
    'IP': ['192.168.1.' + str(i % 256) for i in range(num_white_per_type // 2)],
    'Timestamp': ['[2023-03-26:23:11:20]'] * (num_white_per_type // 2),
    'Method': ['GET'] * (num_white_per_type // 4) + ['POST'] * (num_white_per_type // 8) + ['PUT'] * (num_white_per_type // 8),
    'Path': [f"/pfc/pfc-med/resource{i}.{ext}" for i, ext in enumerate(['jpg', 'png', 'css', 'js'] * (num_white_per_type // 8))],
    'Protocol': ['HTTP/1.1'] * (num_white_per_type // 2),
    'Status': [200] * (num_white_per_type // 2),
    'Size': [np.random.randint(5000, 100000) for _ in range(num_white_per_type // 2)],  # Larger sizes
    'Referer': ['-'] * (num_white_per_type // 2),  # No referer
    'User-Agent': ['Mozilla/5.0'] * (num_white_per_type // 2),
    'Comment': ['white traffic'] * (num_white_per_type // 2),
    'Label': [0] * (num_white_per_type // 2)
})

white_traffic_nested = pd.DataFrame({
    'IP': ['127.0.0.1'] * num_white_per_type,
    'Timestamp': ['[2023-03-26:23:11:20]'] * num_white_per_type,
    'Method': ['GET'] * (num_white_per_type // 2) + ['POST'] * (num_white_per_type // 4) + ['PUT'] * (num_white_per_type // 4),
    'Path': [f"/pfc/med/lib{i}/script{i}.{ext}" for i, ext in enumerate(['js', 'css'] * (num_white_per_type // 2))],
    'Protocol': ['HTTP/1.1'] * num_white_per_type,
    'Status': [200] * num_white_per_type,
    'Size': [np.random.randint(20000, 35000) for _ in range(num_white_per_type)],
    'Referer': ['http://127.0.0.1/imhotep/public/home'] * num_white_per_type,
    'User-Agent': ['Mozilla/5.0'] * num_white_per_type,
    'Comment': ['white traffic'] * num_white_per_type,
    'Label': [0] * num_white_per_type
})

white_traffic_api = pd.DataFrame({
    'IP': ['10.0.0.' + str(i % 256) for i in range(num_white_per_type)],
    'Timestamp': ['[2023-03-26:23:11:20]'] * num_white_per_type,
    'Method': ['GET'] * (num_white_per_type // 2) + ['POST'] * (num_white_per_type // 4) + ['PUT'] * (num_white_per_type // 4),
    'Path': [f"/find/french/getcommune/json/{i}" for i in range(num_white_per_type)],
    'Protocol': ['HTTP/1.1'] * num_white_per_type,
    'Status': [200] * num_white_per_type,
    'Size': [np.random.randint(500, 2000) for _ in range(num_white_per_type)],
    'Referer': ['http://localhost:3000/'] * (num_white_per_type // 2) + ['http://197.207.123.253/cscc_app/login/?error=aaaa'] * (num_white_per_type // 2),
    'User-Agent': ['Mozilla/5.0'] * num_white_per_type,
    'Comment': ['white traffic'] * num_white_per_type,
    'Label': [0] * num_white_per_type
})

# Combine synthetic examples with the original dataset
df = pd.concat([df, xss_entries, command_injection_entries, lfi_entries, white_traffic_static_with_referer, white_traffic_static_no_referer, white_traffic_nested, white_traffic_api], ignore_index=True)
print("\nAugmented Dataset Shape:", df.shape)
print("Augmented Label Distribution:\n", df['Label'].value_counts())

# Step 5: Preprocess and Feature Engineering
df['Referer'] = df['Referer'].replace('-', 'none')
df['Path_Length'] = df['Path'].apply(len)
df['Has_Percent'] = df['Path'].apply(lambda x: 1 if '%20' in x else 0)
df['Has_Equal'] = df['Path'].apply(lambda x: 1 if '=' in x else 0)
df['Has_Script'] = df['Path'].apply(lambda x: 1 if '<script>' in x.lower() else 0)
df['Has_Semicolon'] = df['Path'].apply(lambda x: 1 if ';' in x else 0)
df['Has_DotDot'] = df['Path'].apply(lambda x: 1 if '../' in x else 0)
df['Is_Static_Resource'] = df['Path'].apply(lambda x: 1 if x.endswith(('.jpg', '.png', '.css', '.js', '.json')) else 0)
df['Has_Query_Params'] = df['Path'].apply(lambda x: 1 if '?' in x else 0)
df['Has_Referer'] = df['Referer'].apply(lambda x: 1 if x != 'none' else 0)
df['Referer_Length'] = df['Referer'].apply(len)
df['Status'] = pd.to_numeric(df['Status'])
df['Is_Error_Status'] = df['Status'].apply(lambda x: 1 if x >= 400 else 0)
df['Is_Successful_Status'] = df['Status'].apply(lambda x: 1 if x == 200 else 0)
df['Size'] = pd.to_numeric(df['Size'])
df['Is_API_Path'] = df['Path'].apply(lambda x: 1 if len(x.split('/')) >= 4 else 0)
df['Is_Large_Size'] = df['Size'].apply(lambda x: 1 if x >= 2000 else 0)  # Changed from Is_Small_Size to favor static resources
df['Is_Dev_Referer'] = df['Referer'].apply(lambda x: 1 if any(kw in x.lower() for kw in ['localhost', '127.0.0.1']) else 0)
df['Referer_Has_Query_Params'] = df['Referer'].apply(lambda x: 1 if '?' in x else 0)
df['Is_GET'] = df['Method'].apply(lambda x: 1 if x.upper() == 'GET' else 0)
df['Is_POST'] = df['Method'].apply(lambda x: 1 if x.upper() == 'POST' else 0)
df['Is_Other_Method'] = df['Method'].apply(lambda x: 1 if x.upper() not in ['GET', 'POST'] else 0)
df['Is_Local_IP'] = df['IP'].apply(is_local_ip)
df['Is_Common_IP'] = df['IP'].apply(lambda x: 1 if x in common_ips else 0)
df['IP_First_Octet'] = df['IP'].apply(get_first_octet)

# Select features and target
X = df[['Path_Length', 'Has_Percent', 'Has_Equal', 'Has_Script', 'Has_Semicolon', 'Has_DotDot', 'Is_Static_Resource', 'Has_Query_Params', 'Has_Referer', 'Referer_Length', 'Status', 'Is_Error_Status', 'Is_Successful_Status', 'Size', 'Is_API_Path', 'Is_Large_Size', 'Is_Dev_Referer', 'Referer_Has_Query_Params', 'Is_GET', 'Is_POST', 'Is_Other_Method', 'Is_Local_IP', 'Is_Common_IP', 'IP_First_Octet']]
y = df['Label']

# Step 6: Normalize numerical features
scaler = StandardScaler()
numerical_features = ['Path_Length', 'Referer_Length', 'Status', 'Size', 'IP_First_Octet']
X[numerical_features] = scaler.fit_transform(X[numerical_features])

# Save the scaler for testing
joblib.dump(scaler, 'scaler.pkl')

# Step 7: Split the dataset (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print("\nTraining Set Shape:", X_train.shape)
print("Testing Set Shape:", X_test.shape)

# Step 8: Train the Logistic Regression model with regularization and cross-validation
from sklearn.model_selection import cross_val_score

# First, evaluate with cross-validation
model_cv = LogisticRegression(
    random_state=42,
    class_weight='balanced',  # Automatically adjust weights based on class frequencies
    C=0.5,                   # Regularization strength (smaller values = stronger regularization)
    penalty='l2',            # L2 regularization to prevent extreme coefficients
    max_iter=2000,           # Increased to ensure convergence
    solver='liblinear'       # Better for imbalanced datasets
)

# Perform 5-fold cross-validation
cv_scores = cross_val_score(model_cv, X, y, cv=5, scoring='f1_weighted')
print(f"\nCross-Validation F1 Scores: {cv_scores}")
print(f"Mean CV F1 Score: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")

# Train the final model
model = LogisticRegression(
    random_state=42,
    class_weight='balanced',  # Automatically adjust weights based on class frequencies
    C=0.5,                   # Regularization strength
    penalty='l2',            # L2 regularization
    max_iter=2000,
    solver='liblinear'
)
model.fit(X_train, y_train)

# Step 9: Evaluate the model on the test set with more metrics
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc

# Predict probabilities and classes
y_pred_proba = model.predict_proba(X_test)[:, 1]
y_pred = model.predict(X_test)

# Calculate ROC AUC
roc_auc = roc_auc_score(y_test, y_pred_proba)

# Calculate Precision-Recall AUC
precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
pr_auc = auc(recall, precision)

print("\nModel Evaluation on Test Set:")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"ROC AUC: {roc_auc:.4f}")
print(f"PR AUC: {pr_auc:.4f}")
print("Classification Report:\n", classification_report(y_test, y_pred, target_names=['White Traffic', 'Malicious']))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Calculate and print the false positive rate and false negative rate
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
fpr = fp / (fp + tn)
fnr = fn / (fn + tp)
print(f"False Positive Rate: {fpr:.4f}")
print(f"False Negative Rate: {fnr:.4f}")

# Step 10: Print feature coefficients
print("\nFeature Coefficients:")
feature_names = X.columns
coefficients = model.coef_[0]
for name, coef in zip(feature_names, coefficients):
    print(f"{name}: {coef}")

# Step 11: Save the model
joblib.dump(model, 'traffic_classifier.pkl')
print("Model saved as 'traffic_classifier.pkl'")