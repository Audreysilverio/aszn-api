# fix_deleted_nulls.py
from app import app, db
from sqlalchemy import text

with app.app_context():
    # Se 'deleted' for NULL, força para 0 (False) nos registros antigos
    db.session.execute(text("UPDATE doacoes SET deleted = 0 WHERE deleted IS NULL"))
    db.session.execute(text("UPDATE voluntarios SET deleted = 0 WHERE deleted IS NULL"))
    db.session.commit()
    print("✅ Ajuste feito: deleted=NULL -> 0 nas tabelas doacoes e voluntarios")
