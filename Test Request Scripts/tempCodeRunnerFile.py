    # Test 12: Deregister a server
    print("\n12. Testing server deregistration...")
    deregister_data = {
        "ip": "137.158.61.244",
        "port": 12345
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
    