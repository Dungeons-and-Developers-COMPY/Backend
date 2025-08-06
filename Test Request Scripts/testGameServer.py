import requests

session = requests.Session()

# Login
login = session.post(
    "https://dungeonsanddevelopers.cs.uct.ac.za/admin/login", 
    json={"username": "Ibrahim", "password": "Dnd4Ever!"}
)

print("Login Status:", login.status_code)
try:
    print("Login Response:", login.json())
except Exception:
    print("Login Response (raw):", login.text)

if login.status_code == 200:
    print("\n" + "="*50)
    print("TESTING SERVER ROUTES")
    print("="*50)
    

    print("\n4. Testing second server registration...")
    register_data2 = {
        "ip": "192.168.1.101",
        "port": 8081,
        "type": "2v2",
        "max_players": 4,
        "current_players": 0
    }
    register2 = session.post(
        "https://dungeonsanddevelopers.cs.uct.ac.za/server/register",
        json=register_data2
    )
    print(f"Register2 Status: {register2.status_code}")
    try:
        print(f"Register2 Response: {register2.json()}")
    except:
        print(f"Register2 Response (raw): {register2.text}")
    
    # Test 5: List servers again (should show registered servers)
    print("\n5. Testing list servers (should show 2 servers)...")
    list_servers2 = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/list")
    print(f"List2 Status: {list_servers2.status_code}")
    try:
        print(f"List2 Response: {list_servers2.json()}")
    except:
        print(f"List2 Response (raw): {list_servers2.text}")
        
    # Test 12: Deregister a server
    print("\n12. Testing server deregistration...")
    deregister_data = {
        "ip": "192.168.1.101",
        "port": 8081
    }
    deregister = session.post(
        "https://dungeonsanddevelopers.cs.uct.ac.za/server/deregister",
        json=deregister_data
    )
    print(f"Deregister Status: {deregister.status_code}")
    try:
        print(f"Deregister Response: {deregister.json()}")
    except:
        print(f"Deregister Response (raw): {deregister.text}")
    
    # Test 13: Final server list
    print("\n13. Testing final server list...")
    final_list = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/list")
    print(f"Final List Status: {final_list.status_code}")
    try:
        print(f"Final List Response: {final_list.json()}")
    except:
        print(f"Final List Response (raw): {final_list.text}")
