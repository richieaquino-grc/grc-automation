import os
import requests

token = os.environ.get("GITHUB_TOKEN")

headers = {"Authorization": "Bearer " + token}

response = requests.get("https://api.github.com/user", headers=headers)
data = response.json()

print(response.status_code)
print(data["login"])