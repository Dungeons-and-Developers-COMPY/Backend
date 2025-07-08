import requests


difficulty = 'Easy'
url = f"http://localhost:5000/questions/random/{difficulty}"

auth = ("", "!")

response = requests.get(url, auth=auth)

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)