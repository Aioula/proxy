from flask import Flask, request, redirect, Response
import requests
import re
import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)

# Chargement du modèle, du scaler et des IPs communes
model = joblib.load("traffic_classifier.pkl")
scaler = joblib.load("scaler.pkl")
common_ips = joblib.load("common_ips.pkl")

BLOCKED_PATTERNS = [
    r"union\s+select", r"select\s.+\sfrom", r"insert\s+into", r"delete\s+from",
    r"drop\s+table", r"<script.*?>", r"alert\s*\(", r"onerror\s*=",
    r"eval\s*\(", r"cmd=", r"wget\s+", r"curl\s+", r"\.\./", r"etc/passwd"
]

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

def get_first_octet(ip):
    try:
        return int(ip.split('.')[0])
    except:
        return 0

def is_malicious_rule_based(payload):
    if not payload:
        return False
    return any(re.search(pattern, payload, re.IGNORECASE) for pattern in BLOCKED_PATTERNS)

def preprocess_request_for_ml(ip, method, path, status, size, referer):
    df = pd.DataFrame([{
        'IP': ip,
        'Method': method,
        'Path': path,
        'Status': status,
        'Size': size,
        'Referer': referer or 'none'
    }])
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
    df['Is_Large_Size'] = df['Size'].apply(lambda x: 1 if x >= 2000 else 0)
    df['Is_Dev_Referer'] = df['Referer'].apply(lambda x: 1 if any(kw in x.lower() for kw in ['localhost', '127.0.0.1']) else 0)
    df['Referer_Has_Query_Params'] = df['Referer'].apply(lambda x: 1 if '?' in x else 0)
    df['Is_GET'] = df['Method'].apply(lambda x: 1 if x.upper() == 'GET' else 0)
    df['Is_POST'] = df['Method'].apply(lambda x: 1 if x.upper() == 'POST' else 0)
    df['Is_Other_Method'] = df['Method'].apply(lambda x: 1 if x.upper() not in ['GET', 'POST'] else 0)
    df['Is_Local_IP'] = df['IP'].apply(is_local_ip)
    df['Is_Common_IP'] = df['IP'].apply(lambda x: 1 if x in common_ips else 0)
    df['IP_First_Octet'] = df['IP'].apply(get_first_octet)

    numerical = ['Path_Length', 'Referer_Length', 'Status', 'Size', 'IP_First_Octet']
    df[numerical] = scaler.transform(df[numerical])

    features = [
        'Path_Length', 'Has_Percent', 'Has_Equal', 'Has_Script', 'Has_Semicolon', 'Has_DotDot',
        'Is_Static_Resource', 'Has_Query_Params', 'Has_Referer', 'Referer_Length', 'Status',
        'Is_Error_Status', 'Is_Successful_Status', 'Size', 'Is_API_Path', 'Is_Large_Size',
        'Is_Dev_Referer', 'Referer_Has_Query_Params', 'Is_GET', 'Is_POST', 'Is_Other_Method',
        'Is_Local_IP', 'Is_Common_IP', 'IP_First_Octet'
    ]
    return df[features]

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def proxy(path):
    req_data = request.get_data(as_text=True)
    query_string = request.query_string.decode()
    method = request.method
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    full_path = f"/{path}?{query_string}" if query_string else f"/{path}"

    print(f"[REQUEST] {method} {full_path} from {ip}")

    # Rule-based WAF
    if any(is_malicious_rule_based(v) for v in request.args.values()):
        print("[BLOCKED] Rule-based detection")
        return redirect("http://localhost:5173/blocked")

    if request.is_json and any(is_malicious_rule_based(str(v)) for v in request.json.values()):
        print("[BLOCKED] Rule-based detection (JSON)")
        return redirect("http://localhost:5173/blocked")

    if is_malicious_rule_based(req_data) or is_malicious_rule_based(query_string):
        print("[BLOCKED] Rule-based detection (body/query)")
        return redirect("http://localhost:5173/blocked")

    # ML-based WAF
    ml_input = preprocess_request_for_ml(
        ip=ip,
        method=method,
        path=full_path,
        status=200,
        size=len(req_data),
        referer=request.headers.get("Referer", "-")
    )
    prediction = model.predict(ml_input)[0]
    if prediction == 1:
        print("[BLOCKED] ML model prediction")
        return redirect("http://localhost:5173/blocked")

    # Forwarding to backend
    try:
        backend_response = requests.request(
            method=method,
            url=f"http://localhost:5000/{path}",
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=req_data,
            params=request.args
        )
        # Redirect to frontend if backend 404
        if backend_response.status_code == 404:
            return redirect("http://localhost:5173/normal")
        return Response(
            backend_response.content,
            status=backend_response.status_code,
            headers=dict(backend_response.headers)
        )
    except Exception as e:
        print(f"[ERROR] Failed to reach backend: {e}")
        return Response("Erreur interne du proxy.", status=500)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
