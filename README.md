# Backend

LOG INTO UCT VPN FIRST!!!

## Copy files to server
Windows:
scp -r Backend/my_app abdibr008@dnd-vm-1.cs.uct.ac.za:

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
[http://http://137.158.61.244:5000/admin](https://dungeonsanddevelopers.cs.uct.ac.za/admin)
```

## API 

There are several API endpoints where you can get information from the database.

### 1.) Run Python code before final submission (POST)
Code submissions have to be made with the use of a function (func). The parameter can be anything. 
#### Input
```Python
import requests

BASE_URL = "https://dungeonsanddevelopers.cs.uct.ac.za/admin"
QUESTION_NUMBER = 2
TEST_USERNAME = "NAME HERE"
TEST_PASSWORD = "PASSWORD HERE"

# --- Login ---
login = requests.post(f"{BASE_URL}/login", json={
    "username": TEST_USERNAME,
    "password": TEST_PASSWORD
})

if login.status_code != 200:
    print("Login failed:", login.text)
    exit()

cookies = login.cookies
print("Login successful.")

run_resp = requests.post(f"{BASE_URL}/run-code", json={
    "code": "def func(x): return x * 2",
    "input": "10"
}, cookies=cookies)

print("\nRun Code Result:")
print(run_resp.json() if run_resp.ok else run_resp.text)


```
#### Output
```Python
{'result': 20, 'success': True}
```

### 2.) Send Final Submission Attempt to server (POST)
Code submissions have to be made with the use of a function (func). The parameter can be anything. 
#### Input
```Python
import requests

session = requests.Session()

# Login
login = session.post(
    "https://dungeonsanddevelopers.cs.uct.ac.za/admin/login", 
    json={"username": "NAME HERE", "password": "PASSWORD HERE"}
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

```

#### Output
```Python
{'message': 'All test cases passed!', 'question_number': 5, 'success': True}
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



