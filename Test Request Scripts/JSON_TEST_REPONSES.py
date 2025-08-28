import requests

# --- Configuration ---
BASE_URL = "https://dungeonsanddevelopers.cs.uct.ac.za"
USERNAME = "Ibrahim"
PASSWORD = "Dnd4Ever!"

# --- Start a session ---
session = requests.Session()

# --- Login ---
login_resp = session.post(
    f"{BASE_URL}/admin/login",
    json={"username": USERNAME, "password": PASSWORD}
)

print("Login status:", login_resp.status_code)
try:
    print("Login response:", login_resp.json())
except Exception:
    print("Login response (raw):", login_resp.text)


# --- Get leaderboard ---
leaderboard_url = f"{BASE_URL}/server/leaderboard"
leaderboard_resp = session.get(leaderboard_url)

print("\n--- Leaderboard Response ---")
try:
    print(leaderboard_resp.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", leaderboard_resp.status_code)
    print("Raw response:", leaderboard_resp.text)