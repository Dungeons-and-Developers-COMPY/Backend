import requests

BASE_URL = "https://dungeonsanddevelopers.cs.uct.ac.za"
session = requests.Session()

SERVER_KEY = "4fIEjhIwkfIIPcU2m4vYDdLe0ZFkDgzh"

# --- Test 1: Username/Password Login (for normal user/admin routes) ---
print("\n=== Testing username/password login ===")
login_pw = session.post(
    f"{BASE_URL}/admin/login",
    json={"username": "Ibrahim", "password": "Dnd4Ever!"}
)

print("Login (username/password) Status:", login_pw.status_code)
try:
    print("Login Response:", login_pw.json())
except Exception:
    print("Login Response (raw):", login_pw.text)


# --- Test 2: Test Decrement Players using SERVER KEY ---
print("\n=== Testing decrement-players with server key ===")
decrement_resp = requests.post(
    f"{BASE_URL}/server/decrement-players",
    headers={"ServerKey": SERVER_KEY, "Content-Type": "application/json"},
    json={"ip": "137.158.61.244", "port": 12341}
)

print("Decrement Status:", decrement_resp.status_code)
try:
    print("Decrement Response:", decrement_resp.json())
except Exception:
    print("Decrement Response (raw):", decrement_resp.text)
