import random
import string

from my_app import create_app, db
from models import User

# App context setup
app = create_app()
app.app_context().push()

# Parameters
NUM_USERS = 100
USERNAME_PREFIX = "student"
PASSWORD_LENGTH = 10
OUTPUT_FILE = "student_credentials.txt"

def generate_username(index: int) -> str:
    return f"{USERNAME_PREFIX}{index:03d}"  # student001, student002, ...

def generate_password(length: int = PASSWORD_LENGTH) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

credentials = []

for i in range(1, NUM_USERS + 1):
    username = generate_username(i)
    password = generate_password()
    
    # Create and store user
    user = User(username=username, role="student")
    user.set_password(password)
    db.session.add(user)

    # Save for output file
    credentials.append(f"{username} {password}")

# Commit to DB
db.session.commit()

# Write to file
with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(credentials))

print(f"✅ Created {NUM_USERS} student users.")
print(f"📝 Credentials saved to: {OUTPUT_FILE}")
