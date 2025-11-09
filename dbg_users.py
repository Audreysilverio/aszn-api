# dbg_users.py
from app import app, db, User

with app.app_context():
    print("DB URL:", app.config["SQLALCHEMY_DATABASE_URI"])
    users = User.query.all()
    if not users:
        print("Nenhum usuário.")
    else:
        for u in users:
            print(f"- id={u.id} | email={u.email} | nome={u.nome}")
