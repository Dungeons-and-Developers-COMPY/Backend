import requests

question_number = 3
url = f"http://localhost:5000/questions/stats/{question_number}"

# Your code that should be tested against the test cases
code_submission = r"""
def func(word):
    return word[::-1]
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
    

# Random
difficulty = 'easy'
response = requests.get(f"http://localhost:5000/questions/random/{difficulty}")

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
    