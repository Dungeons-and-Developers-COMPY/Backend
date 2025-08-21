import requests
import base64

# --- Configuration ---
BASE_URL = "https://dungeonsanddevelopers.cs.uct.ac.za/admin"
USERNAME = "Mahir"
PASSWORD = "MrMoodles123!"


# --- Start a session ---
session = requests.Session()

# Optional: log in first if your endpoint requires session auth
login_resp = session.post(
    f"{BASE_URL}/login",
    json={"username": USERNAME, "password": PASSWORD}
)

print("Login Status:", login_resp.status_code)
try:
    print("Login Response:", login_resp.json())
except Exception:
    print("Login Response (raw):", login_resp.text)

QUESTION_NUMBER = 14
# --- Code submission ---
raw_code = """
def func(n):
    return (n + 5) * 2

"""

# Encode in base64 (your backend tries to decode if it looks like base64)
encoded_code = base64.b64encode(raw_code.encode("utf-8")).decode("utf-8")

payload = {"code": encoded_code}

submit_url = f"{BASE_URL}/submit/{QUESTION_NUMBER}"

# If basic auth is required
auth = (USERNAME, PASSWORD)

response = session.post(submit_url, json=payload, auth=auth)

print("\n--- Submission Response ---")
try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
