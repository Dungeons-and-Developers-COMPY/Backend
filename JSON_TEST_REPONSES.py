import requests


question_number = 1 # Change this to the actual question number you want to test
url = f"http://localhost:5000/questions/stats/{question_number}"

# Your code that should be tested against the test cases
code_submission = """
for i in range(1, 6):
    print('*' * i)
"""

payload = {
    "code": code_submission
}

response = requests.post(url, json=payload)

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)

#----------------------------------------------------------------------------------
# The following returns a JSON format of the statistics for a particular question
response = requests.get(f"http://localhost:5000/questions/stats/{question_number}")

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
    


response = requests.get(f"http://localhost:5000/questions/random/easy")

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
    