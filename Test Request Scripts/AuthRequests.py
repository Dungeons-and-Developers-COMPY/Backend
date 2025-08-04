import requests

session = requests.Session()

# Login
login = session.post(
    "http://127.0.0.1:5000/admin/login", 
    json={"username": "Ibrahim", "password": "Dnd4ever!"}
)


print("Login Status:", login.status_code)
try:
    print("Login Response:", login.json())
except Exception:
    print("Login Response (raw):", login.text)


question = 5
response = session.get(
    f"http://127.0.0.1:5000/admin/question/1/difficulty",
)
try:
    print("Response JSON:", response.json())
except Exception:
    print("Response Text:", response.text)
