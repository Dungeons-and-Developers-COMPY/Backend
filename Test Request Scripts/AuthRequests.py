import requests

url = "https://dungeonsanddevelopers.cs.uct.ac.za/admin/run-code"

payload = {
    "code": """
def func(word):
    return word[::
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
