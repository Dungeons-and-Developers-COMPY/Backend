input_file = "Backend\Test Request Scripts\serverCredentials.txt"
output_file = "user_snippets.txt"

with open(input_file, "r") as f:
    lines = [line.strip() for line in f if line.strip()]

with open(output_file, "w") as f_out:
    for line in lines:
        username, password = line.split()
        snippet = f"""# Create user {username}
u = User(username="{username}", role="student")
u.set_password("{password}")
db.session.add(u)
db.session.commit()
print("User created:", u.username, u.role)

"""
        f_out.write(snippet)

print(f"Python snippets for each user have been written to {output_file}")
