from my_app import create_app, db
from models import User

app = create_app()
app.app_context().push()

admin = User(username="", role="admin")
admin.set_password("")  

db.session.add(admin)
db.session.commit()

print(f"Admin user created with ID: {admin.id}")

