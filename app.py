# app.py
import os
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

from dotenv import load_dotenv
load_dotenv()


# ---------- Config ----------
app = Flask(__name__)
CORS(app)  # em produção, restrinja origins

# DATABASE_URL exemplo: postgres://user:pass@host:5432/dbname
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# JWT
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "troque_essa_chave_em_producao")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ---------- Models ----------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(240), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    nome = db.Column(db.String(200))

    def set_password(self, senha):
        self.password_hash = generate_password_hash(senha)

    def check_password(self, senha):
        return check_password_hash(self.password_hash, senha)


class Doacao(db.Model):
    __tablename__ = "doacoes"
    id = db.Column(db.Integer, primary_key=True)
    doador_nome = db.Column(db.String(200), nullable=False)
    doador_email = db.Column(db.String(240), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)  # dinheiro, alimento, livro, roupa, outro
    valor = db.Column(db.Float, nullable=True)
    descricao = db.Column(db.Text, nullable=True)
    imagem_url = db.Column(db.Text, nullable=True)
    telefone = db.Column(db.String(50))
    status = db.Column(db.String(50), nullable=False, default="pendente")
    criado_em = db.Column(db.DateTime, server_default=db.func.now())


class Voluntario(db.Model):
    __tablename__ = "voluntarios"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(240), nullable=False)
    telefone = db.Column(db.String(50))
    area_interesse = db.Column(db.String(200))
    disponibilidade = db.Column(db.String(200))
    observacoes = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, default="pendente")
    criado_em = db.Column(db.DateTime, server_default=db.func.now())


# ---------- Helpers ----------
def to_dict(model):
    out = {}
    for c in model.__table__.columns:
        val = getattr(model, c.name)
        out[c.name] = str(val) if isinstance(val, (db.DateTime,)) and val is not None else val
    return out


def validar_email(email: str) -> bool:
    return isinstance(email, str) and "@" in email and "." in email


# ---------- Routes - Auth ----------
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    senha = data.get("senha")
    nome = (data.get("nome") or "").strip()
    if not email or not senha:
        return jsonify({"ok": False, "erro": "email e senha obrigatórios"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"ok": False, "erro": "usuário já existe"}), 400
    u = User(email=email, nome=nome)
    u.set_password(senha)
    db.session.add(u)
    db.session.commit()
    return jsonify({"ok": True, "mensagem": "usuário criado"}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    senha = data.get("senha")
    if not email or not senha:
        return jsonify({"ok": False, "erro": "email e senha obrigatórios"}), 400
    u = User.query.filter_by(email=email).first()
    if not u or not u.check_password(senha):
        return jsonify({"ok": False, "erro": "credenciais inválidas"}), 401

    # ✅ Corrigido: identity precisa ser string
    token = create_access_token(
        identity=str(u.id),
        additional_claims={"email": u.email, "nome": u.nome}
    )
    return jsonify({"ok": True, "access_token": token}), 200


# ---------- Routes - Public ----------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"ok": True, "mensagem": "API ASZN Digital - Doações & Voluntariado"})


@app.route("/doacoes", methods=["POST"])
def criar_doacao():
    d = request.get_json() or {}
    doador_nome = (d.get("doador_nome") or "").strip()
    doador_email = (d.get("doador_email") or "").strip()
    tipo = (d.get("tipo") or "").strip().lower()
    valor = d.get("valor")
    descricao = (d.get("descricao") or "").strip()
    imagem_url = (d.get("imagem_url") or "").strip()
    telefone = (d.get("telefone") or "").strip() 
    erros = []
    if not doador_nome:
        erros.append("doador_nome obrigatório")
    if not validar_email(doador_email):
        erros.append("doador_email inválido")
    if tipo not in {"dinheiro", "alimento", "livro", "roupa", "outro"}:
        erros.append("tipo inválido")
    if tipo == "dinheiro":
        try:
            if float(valor) <= 0:
                erros.append("valor deve ser > 0")
        except Exception:
            erros.append("valor deve ser numérico")
    if erros:
        return jsonify({"ok": False, "erros": erros}), 400
    dd = Doacao(
        doador_nome=doador_nome,
        doador_email=doador_email,
        tipo=tipo,
        valor=valor,
        descricao=descricao,
        imagem_url=imagem_url,
        telefone=telefone,
    )
    db.session.add(dd)
    db.session.commit()
    return jsonify({"ok": True, "doacao": to_dict(dd)}), 201


@app.route("/voluntarios", methods=["POST"])
def criar_voluntario_publico():
    d = request.get_json() or {}
    nome = (d.get("nome") or "").strip()
    email = (d.get("email") or "").strip()
    telefone = (d.get("telefone") or "").strip()
    area = (d.get("area_interesse") or "").strip()
    disponibilidade = (d.get("disponibilidade") or "").strip()
    observacoes = (d.get("observacoes") or "").strip()
    erros = []
    if not nome:
        erros.append("nome obrigatório")
    if not validar_email(email):
        erros.append("email inválido")
    if erros:
        return jsonify({"ok": False, "erros": erros}), 400
    v = Voluntario(
        nome=nome,
        email=email,
        telefone=telefone,
        area_interesse=area,
        disponibilidade=disponibilidade,
        observacoes=observacoes,
    )
    db.session.add(v)
    db.session.commit()
    return jsonify({"ok": True, "voluntario": to_dict(v)}), 201


# ---------- Routes - Protected (admin) ----------
@app.route("/admin/doacoes", methods=["GET"])
@jwt_required()
def admin_list_doacoes():
    q = Doacao.query.order_by(Doacao.criado_em.desc()).limit(200).all()
    return jsonify({"ok": True, "doacoes": [to_dict(x) for x in q]})


@app.route("/admin/doacoes/<int:id>/status", methods=["PUT"])
@jwt_required()
def admin_update_doacao_status(id):
    data = request.get_json() or {}
    novo = (data.get("status") or "").strip().lower()
    if novo not in {"pendente", "confirmada", "cancelada"}:
        return jsonify({"ok": False, "erro": "status inválido"}), 400
    d = Doacao.query.get(id)
    if not d:
        return jsonify({"ok": False, "erro": "doação não encontrada"}), 404
    d.status = novo
    db.session.commit()
    return jsonify({"ok": True, "doacao": to_dict(d)})


@app.route("/admin/voluntarios", methods=["GET"])
@jwt_required()
def admin_list_voluntarios():
    q = Voluntario.query.order_by(Voluntario.criado_em.desc()).limit(200).all()
    return jsonify({"ok": True, "voluntarios": [to_dict(x) for x in q]})


@app.route("/admin/voluntarios/<int:id>/status", methods=["PUT"])
@jwt_required()
def admin_update_vol_status(id):
    data = request.get_json() or {}
    novo = (data.get("status") or "").strip().lower()
    if novo not in {"pendente", "aprovado", "recusado"}:
        return jsonify({"ok": False, "erro": "status inválido"}), 400
    v = Voluntario.query.get(id)
    if not v:
        return jsonify({"ok": False, "erro": "voluntário não encontrado"}), 404
    v.status = novo
    db.session.commit()
    return jsonify({"ok": True, "voluntario": to_dict(v)})


@app.route("/admin/voluntarios/<int:id>", methods=["DELETE"])
@jwt_required()
def admin_delete_vol(id):
    v = Voluntario.query.get(id)
    if not v:
        return jsonify({"ok": False, "erro": "voluntário não encontrado"}), 404
    db.session.delete(v)
    db.session.commit()
    return jsonify({"ok": True, "mensagem": "voluntário removido"})


# ---------- Run ----------
# ---------- Run ----------
from sqlalchemy import inspect, text

if __name__ == "__main__":
    try:
        with app.app_context():
            db.create_all()
            # 🔄 adicionar coluna telefone na tabela doacoes se não existir
            insp = inspect(db.engine)
            colnames = [c["name"] for c in insp.get_columns("doacoes")]
            if "telefone" not in colnames:
                dialect = db.engine.url.get_dialect().name  # "postgresql", "sqlite", etc.
                if dialect == "postgresql":
                    db.session.execute(text('ALTER TABLE doacoes ADD COLUMN telefone VARCHAR(50);'))
                else:
                    # SQLite aceita ADD COLUMN simples
                    db.session.execute(text('ALTER TABLE doacoes ADD COLUMN telefone TEXT;'))
                db.session.commit()
                print("✅ Coluna 'telefone' adicionada em 'doacoes'.")
            print("✅ Banco de dados sincronizado com sucesso.")
    except Exception as e:
        print("⚠️ Erro ao criar/atualizar tabelas:", e)

    # ⬇️ mantém essa linha original do seu app
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
