# dbg_reset_user.py
from app import app, db, User
from werkzeug.security import generate_password_hash

EMAIL = "admin@aszn.org"   # deixe esse mesmo, é o que está no banco
NOVA_SENHA = "123456"      # pode trocar se quiser

with app.app_context():
    u = User.query.filter_by(email=EMAIL.lower().strip()).first()
    if not u:
        print("Usuário não encontrado:", EMAIL)
    else:
        u.password_hash = generate_password_hash(NOVA_SENHA)
        db.session.commit()
        print("✅ Senha trocada para", EMAIL)
