import requests

session = requests.Session()

# 1. Login
login = session.post(
    "https://dungeonsanddevelopers.cs.uct.ac.za/admin/login", 
    json={"username": "Mahir", "password": "MrMoodles123!"}
)

print("Login Status:", login.status_code)
try:
    print("Login Response:", login.json())
except Exception:
    print("Login Response (raw):", login.text)


if login.status_code == 200:
    # 2. Test listing servers (optional check)
    list_servers = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/leaderboard")
    print(f"\nList Status: {list_servers.status_code}")
    try:
        print(f"List Response: {list_servers.json()}")
    except:
        print(f"List Response (raw): {list_servers.text}")

    # 3. Remove a player from leaderboard
    #remove_data = {
    #    "username": "student001"   # 🔹 Change this to the username you want to remove
    #}
    #remove = session.post(
    #    "https://dungeonsanddevelopers.cs.uct.ac.za/server/remove-from-leaderboard",
    #    json=remove_data
    #)
    #print(f"\nRemove Status: {remove.status_code}")
    #try:
    #    print(f"Remove Response: {remove.json()}")
    #except:
    #    print(f"Remove Response (raw): {remove.text}")
