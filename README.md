# Backend

LOG INTO UCT VPN FIRST!!!

## Copy files to server
Windows:
scp -r Backend abdibr008@dnd-vm-1.cs.uct.ac.za:

## Running code on the server
```Python
cd Backend
docker-compose up --build
```
On the UCT server launch in detached mode (-d) so it runs after the window is closed.
```Python
sudo docker compose up -d
```
Acess the admin portal through the following link:
```Python
http://http://137.158.61.244:5000/admin
```

## API 

There are several API endpoints where you can get information from the database.

### 1.) Run Python code before final submission (POST)
Code submissions have to be made with the use of a function (func). The parameter can be anything. 
#### Input
```Python
import requests

url = "https://dungeonsanddevelopers.cs.uct.ac.za/admin/run-code"

payload = {
    "code": """
def func(word):
    return word[::-1]
""",
    "input": "'hello'"
}

response = requests.post(url, json=payload)

try:
    data = response.json()
    if data.get("success"):
        print("Returned value from func():", data["result"])
    else:
        print("Execution failed:", data.get("error"))
except Exception:
    print("Invalid response")
    print(response.status_code)
    print(response.text)
```
#### Output
```Python
Returned value from func(): olleh
```

### 2.) Send Final Submission Attempt to server (POST)
Code submissions have to be made with the use of a function (func). The parameter can be anything. 
#### Input
```Python
import requests

question_number = 3
url = f"https://dungeonsanddevelopers.cs.uct.ac.za/admin/questions/stats/{question_number}"

# Code to be tested against the test cases
code_submission = """
def func(word):
    return word[::-1]
"""

payload = {
    "code": code_submission
}

# Provide your admin username and password here
auth = ("Admin_Username", "Admin_Password")

response = requests.post(url, json=payload, auth=auth)

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)

```

#### Output
```Python
{'message': 'All test cases passed!', 'question_number': 3, 'success': True}
OR
{'error': 'Invalid credentials'}
```
### 3.) Get a random question for a difficulty (Easy, Medium, Hard) (GET)
#### Input
```Python
import requests


difficulty = 'Easy'
url = f"https://dungeonsanddevelopers.cs.uct.ac.za/questions/random/{difficulty}"

auth = ("Admin_Username", "Admin_Password!")

response = requests.get(url, auth=auth)

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
```
#### Output
```Python
{'difficulty': 'easy', 'id': 1, 'prompt_md': 'Print the following pyramid of stars:\n*\n**\n***\n****\n*****', 'question_number': 1, 'tags': 'loop,print', 'test_cases': '[\n  {\n    "input": "",\n    "output": "*\\n**\\n***\\n****\\n*****"\n  }\n]\n', 'title': 'Pyramid of Stars'}
OR
{'error': 'Invalid credentials'}
```

### 4.) Get submission statistics for a particular question (GET)
#### Input
```Python
import requests

question_number = 3
url = f"https://dungeonsanddevelopers.cs.uct.ac.za/questions/stats/{question_number}"

auth = ("Admin_Username", "Admin_Password")

response = requests.get(url, auth=auth)

try:
    print(response.json())
except Exception:
    print("Non-JSON response received:")
    print("Status code:", response.status_code)
    print("Raw response:", response.text)
```
#### Output
```Python
[{'tag': 'slicing', 'total_attempts': 6, 'total_passed': 6}]
OR
{'error': 'Invalid credentials'}
```



