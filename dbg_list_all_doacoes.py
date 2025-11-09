# dbg_list_all_doacoes.py
from app import app, db, Doacao

with app.app_context():
    qs = Doacao.query.order_by(Doacao.id.asc()).all()
    if not qs:
        print("Sem doacoes no banco atual.")
    else:
        for d in qs:
            print(f"id={d.id}  nome={d.doador_nome}  criado_em={d.criado_em}  deleted={d.deleted}")
