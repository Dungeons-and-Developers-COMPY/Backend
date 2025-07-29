import requests

question_number = 2
url = f"https://dungeonsanddevelopers.cs.uct.ac.za/admin/questions/stats/{question_number}"

# Code to be tested against the test cases
code_submission = r"""
def func(word):
    answer = ""
    for i in range(5, 0, -1):
        answer += "*" * i + "\n"
    return answer
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
