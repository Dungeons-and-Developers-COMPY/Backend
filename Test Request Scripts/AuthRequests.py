import requests

session = requests.Session()

# Login
login = session.post(
    "https://dungeonsanddevelopers.cs.uct.ac.za/admin/login", 
    json={"username": "", "password": ""}
)


print("Login Status:", login.status_code)
try:
    print("Login Response:", login.json())
except Exception:
    print("Login Response (raw):", login.text)


question = 5
response = session.post(
    f"https://dungeonsanddevelopers.cs.uct.ac.za/admin/submit/{question}",
    json={"code": r"def func(n): return n"}
)
try:
    print("Response JSON:", response.json())
except Exception:
    print("Response Text:", response.text)
