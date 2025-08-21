import requests

session = requests.Session()

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
    list_servers = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/list")
    print(f"List Status: {list_servers.status_code}")
    try:
        print(f"List Response: {list_servers.json()}")
    except:
        print(f"List Response (raw): {list_servers.text}")

    #print("\n12. Testing server deregistration...")
    #deregister_data = {
    #    "ip": "197.239.190.104",
    #    "port": 12343
    #}
    #deregister = session.post(
    #    "https://dungeonsanddevelopers.cs.uct.ac.za/server/deregister",
    #    json=deregister_data
    #)
    #try:
    #    print(f"List Response: {deregister.json()}")
    #except:
    #    print(f"List Response (raw): {deregister.text}")