import requests

# --- Configuration ---
BASE_URL = "https://dungeonsanddevelopers.cs.uct.ac.za/admin"
USERNAME = "Mahir"
PASSWORD = "MrMoodles123!"

# --- Start a session ---
session = requests.Session()

# --- Login ---
login_resp = session.post(
    f"{BASE_URL}/login",
    json={"username": USERNAME, "password": PASSWORD}
)

print("Login status:", login_resp.status_code)
try:
    print("Login response:", login_resp.json())
except Exception:
    print("Login response (raw):", login_resp.text)

# --- Update user time ---
update_time_url = f"https://dungeonsanddevelopers.cs.uct.ac.za/server/update-time"
user_to_update = "student002"  # change to the username you want to update
new_time = 12.3 # new time in seconds (float)

update_resp = session.post(
    update_time_url,
    json={"username": user_to_update, "time": new_time}
)

print("\n--- Update Time Response ---")
try:
    print(update_resp.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", update_resp.status_code)
    print("Raw response:", update_resp.text)

# --- Get leaderboard ---
leaderboard_url = f"https://dungeonsanddevelopers.cs.uct.ac.za/server/leaderboard"

leaderboard_resp = session.get(leaderboard_url)

print("\n--- Leaderboard Response ---")
try:
    print(leaderboard_resp.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", leaderboard_resp.status_code)
    print("Raw response:", leaderboard_resp.text)
