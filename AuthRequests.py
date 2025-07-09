import requests

question_number = 4
url = f"http://137.158.61.244:5000/questions/stats/{question_number}"

# Code to be tested against the test cases
code_submission = """
def func(word):
    return word[::-1]
"""

payload = {
    "code": code_submission
}

# Provide your admin username and password here
auth = ("Ibrahim", "Dnd4Ever!")

response = requests.post(url, json=payload, auth=auth)

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
