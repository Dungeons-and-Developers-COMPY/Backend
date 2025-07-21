import requests

question_number = 3
url = f"https://dungeonsanddevelopers.cs.uct.ac.za/admin/questions/stats/{question_number}"

# Code to be tested against the test cases
code_submission =r"""
def func(word):
"""
# yes = if word == word[::1]: return true else: return false
payload = {
    "code": code_submission
}

auth = ("Ibrahim", "Dnd4Ever!")

response = requests.post(url, json=payload, auth=auth)

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)

#----------------------------------------------------------------------------------
# The following returns a JSON format of the statistics for a particular question
"""
response = requests.get(f"https://dungeonsanddevelopers.cs.uct.ac.za/admin/question-pass-stats")

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
    
"""
# Random
"""
difficulty = 'easy'
response = requests.get(f"http://localhost:5000/questions/random/{difficulty}")

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
"""
