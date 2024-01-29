import requests
import json

url = 'http://localhost:8000/api/onboarding/api/merchant/register'

# data = {
#     "username": "john_doe",
#     "password": "securepassword",
#     "email": "john@example.com",
#     "first_name": "John",
#     "last_name": "Doe"
# }

# response = requests.post(url, json=data)
# print(data)

# Read the data from the JSON file
with open('register.json', 'r') as json_file:
    data = json.load(json_file)

response = requests.post(url, json=data)
# print(data)

if response.status_code == 201:
    print("Merchant registered successfully!")
else:
    print(f"Error: {response.status_code}, {response.text}")
