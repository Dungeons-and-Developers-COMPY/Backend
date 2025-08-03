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
    
    # Test 1: Health Check
    print("\n1. Testing health check...")
    health = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/health")
    print(f"Health Status: {health.status_code}")
    try:
        print(f"Health Response: {health.json()}")
    except:
        print(f"Health Response (raw): {health.text}")
    
    # Test 2: List servers (should be empty initially)
    print("\n2. Testing list servers (should be empty)...")
    list_servers = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/list")
    print(f"List Status: {list_servers.status_code}")
    try:
        print(f"List Response: {list_servers.json()}")
    except:
        print(f"List Response (raw): {list_servers.text}")
    
    # Test 3: Register a new server
    print("\n3. Testing server registration...")
    register_data = {
        "ip": "192.168.1.100",
        "port": 8080,
        "type": "1v1",
        "max_players": 2,
        "current_players": 0
    }
    register = session.post(
        "https://dungeonsanddevelopers.cs.uct.ac.za/server/register",
        json=register_data
    )
    print(f"Register Status: {register.status_code}")
    try:
        print(f"Register Response: {register.json()}")
    except:
        print(f"Register Response (raw): {register.text}")
    
    # Test 4: Register another server (2v2)
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
    
    # Test 6: Find available server (any type)
    print("\n6. Testing find available server (any type)...")
    find_any = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/find-available")
    print(f"Find Any Status: {find_any.status_code}")
    try:
        print(f"Find Any Response: {find_any.json()}")
    except:
        print(f"Find Any Response (raw): {find_any.text}")
    
    # Test 7: Find available server (1v1 only)
    print("\n7. Testing find available server (1v1 only)...")
    find_1v1 = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/find-available?type=1v1")
    print(f"Find 1v1 Status: {find_1v1.status_code}")
    try:
        print(f"Find 1v1 Response: {find_1v1.json()}")
    except:
        print(f"Find 1v1 Response (raw): {find_1v1.text}")
    
    # Test 8: Update player count
    print("\n8. Testing update player count...")
    update_data = {
        "ip": "192.168.1.100",
        "port": 8080,
        "current_players": 1
    }
    update = session.post(
        "https://dungeonsanddevelopers.cs.uct.ac.za/server/update-players",
        json=update_data
    )
    print(f"Update Status: {update.status_code}")
    try:
        print(f"Update Response: {update.json()}")
    except:
        print(f"Update Response (raw): {update.text}")
    
    # Test 9: Get specific server status
    print("\n9. Testing get server status...")
    status = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/status/192.168.1.100/8080")
    print(f"Status Status: {status.status_code}")
    try:
        print(f"Status Response: {status.json()}")
    except:
        print(f"Status Response (raw): {status.text}")
    
    # Test 10: Fill up the 1v1 server
    print("\n10. Testing filling up 1v1 server...")
    update_full = session.post(
        "https://dungeonsanddevelopers.cs.uct.ac.za/server/update-players",
        json={"ip": "192.168.1.100", "port": 8080, "current_players": 2}
    )
    print(f"Update Full Status: {update_full.status_code}")
    try:
        print(f"Update Full Response: {update_full.json()}")
    except:
        print(f"Update Full Response (raw): {update_full.text}")
    
    # Test 11: Try to find 1v1 server (should return 2v2 server now)
    print("\n11. Testing find available after 1v1 is full...")
    find_after_full = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/find-available")
    print(f"Find After Full Status: {find_after_full.status_code}")
    try:
        print(f"Find After Full Response: {find_after_full.json()}")
    except:
        print(f"Find After Full Response (raw): {find_after_full.text}")
    
    # Test 12: Deregister a server
    print("\n12. Testing server deregistration...")
    deregister_data = {
        "ip": "192.168.1.100",
        "port": 8080
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
    
    # Test 14: Error cases - Try to access non-existent server
    print("\n14. Testing error case - non-existent server status...")
    error_status = session.get("https://dungeonsanddevelopers.cs.uct.ac.za/server/status/999.999.999.999/9999")
    print(f"Error Status: {error_status.status_code}")
    try:
        print(f"Error Response: {error_status.json()}")
    except:
        print(f"Error Response (raw): {error_status.text}")
    
    # Test 15: Error cases - Invalid registration data
    print("\n15. Testing error case - invalid registration...")
    invalid_register = session.post(
        "https://dungeonsanddevelopers.cs.uct.ac.za/server/register",
        json={"ip": "192.168.1.200"}  # Missing required fields
    )
    print(f"Invalid Register Status: {invalid_register.status_code}")
    try:
        print(f"Invalid Register Response: {invalid_register.json()}")
    except:
        print(f"Invalid Register Response (raw): {invalid_register.text}")

else:
    print("Login failed, cannot test server routes")