import requests

# --- Configuration ---
BASE_URL = "https://dungeonsanddevelopers.cs.uct.ac.za"
USERNAME = "Ibrahim"
PASSWORD = "Dnd4Ever!"

# --- Configure your submission here ---
TAG_NAME = "abs"  # Change this to the tag you want
PASSED = True        # Change this to False for incorrect submission

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

if login_resp.status_code != 200:
    print("Login failed, exiting...")
    exit(1)

# --- Add single submission to tag ---
print(f"\n--- Adding {'CORRECT' if PASSED else 'INCORRECT'} submission to tag '{TAG_NAME}' ---")

submission_url = f"{BASE_URL}/admin/tags/{TAG_NAME}/submissions"
submission_resp = session.post(
    submission_url,
    json={"passed": PASSED}
)

print(f"Status: {submission_resp.status_code}")

try:
    response_data = submission_resp.json()
    if submission_resp.status_code == 200:
        stats = response_data.get("updated_stats", {})
        print(f"✅ Success! Updated stats for '{TAG_NAME}':")
        print(f"   Total Attempts: {stats.get('total_attempts')}")
        print(f"   Total Passed: {stats.get('total_passed')}")
        print(f"   Total Failed: {stats.get('total_failed')}")
        print(f"   Pass Rate: {stats.get('pass_rate')}%")
    else:
        print(f"❌ Error: {response_data.get('error', 'Unknown error')}")
except Exception:
    print(f"Non-JSON response: {submission_resp.text}")