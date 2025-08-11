import requests

BASE_URL = "https://dungeonsanddevelopers.cs.uct.ac.za"
session = requests.Session()

# --- Test 1: Username/Password Login ---
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

# --- Test 2: Special Key Login ---
print("\n=== Testing special key login ===")
login_key = session.post(
    f"{BASE_URL}/admin/login", 
    json={"login_key": "4fIEjhIwkfIIPcU2m4vYDdLe0ZFkDgzh"}
)

print("Login (key) Status:", login_key.status_code)
try:
    print("Login Response:", login_key.json())
except Exception:
    print("Login Response (raw):", login_key.text)


# If either login worked, test protected route
if login_pw.status_code == 200 or login_key.status_code == 200:
    print("\n" + "=" * 50)
    print("TESTING SERVER ROUTES")
    print("=" * 50)

    print("\n1. Testing final server list...")
    final_list = session.get(f"{BASE_URL}/server/list")
    print(f"Final List Status: {final_list.status_code}")
    try:
        print(f"Final List Response: {final_list.json()}")
    except:
        print(f"Final List Response (raw): {final_list.text}")
