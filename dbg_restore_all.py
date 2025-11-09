# dbg_restore_all.py
from app import app, db
from sqlalchemy import text

with app.app_context():
    db.session.execute(text("UPDATE doacoes SET deleted=0 WHERE deleted=1 OR deleted IS NULL"))
    db.session.commit()
    print("✅ Todos os 'deleted' ajustados para 0.")
