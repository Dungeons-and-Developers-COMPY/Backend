# Backend

# Copy files to server

For your first time running the files do the following

cp -r Backend abdibr008@dnd-vm-1.cs.uct.ac.za:

Install the following two applications:

1.) Docker

```Python
https://www.docker.com/products/docker-desktop/
```

2.) PostgreSQL
```Python
https://www.enterprisedb.com/downloads/postgres-postgresql-downloads
```

Once docker is installed, your computer will restart and will be able to run the following command after "cd Backend"
```Python
docker-compose up --build
```

Acess the admin portal through the following link:
```Python
http://127.0.0.1:5000/admin
```

## API 

There are several API endpoints where you can get information from the database.

### 1.) Send Submission Attempt to server (POST)
#### Input
```Python
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
response = requests.get(f"http://localhost:5000/questions/stats/{question_number}")

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
```

### 2.) Get submission statistics for a particular question (GET)
#### Input
```Python
import requests

question_number = 3
response = requests.get(f"http://localhost:5000/questions/stats/{question_number}")

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
```


### 3.) Get a random question for a difficulty (Easy, Medium, Hard) (GET)
#### Input
```Python
import requests

difficulty = 'Easy'
response = requests.get(f"http://localhost:5000/questions/random/{difficulty}")

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
```


