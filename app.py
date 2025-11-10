# app.py
import os
from datetime import timedelta, datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required
)
from dotenv import load_dotenv
from sqlalchemy import text, inspect

# Carrega variáveis de ambiente (localmente)
load_dotenv()

# ---------- Config ----------
app = Flask(__name__)
CORS(app)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "troque_essa_chave_em_producao")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)

# 🚀 CORREÇÃO 1: Adiciona o parâmetro SSL/TLS para o PostgreSQL no Render
if DATABASE_URL.startswith("postgresql://"):
    # O 'sslmode=require' é obrigatório na maioria dos provedores de nuvem
    # para garantir a segurança da conexão.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {
            "sslmode": "require"
        }
    }

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
    tipo = db.Column(db.String(50), nullable=False)
    valor = db.Column(db.Float, nullable=True)
    descricao = db.Column(db.Text, nullable=True)
    imagem_url = db.Column(db.Text, nullable=True)
    telefone = db.Column(db.String(50))
    status = db.Column(db.String(50), nullable=False, default="pendente")
    criado_em = db.Column(db.DateTime, server_default=db.func.now())
    deleted = db.Column(db.Boolean, default=False)


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
    deleted = db.Column(db.Boolean, default=False)


# ---------- Helpers ----------
def to_dict(model):
    out = {}
    for c in model.__table__.columns:
        val = getattr(model, c.name)
        # Serializa datetime de forma segura
        if isinstance(val, datetime):
            out[c.name] = val.isoformat()
        else:
            out[c.name] = val
    return out

def validar_email(email: str) -> bool:
    return isinstance(email, str) and "@" in email and "." in email

def is_sqlite_uri(uri: str) -> bool:
    return uri.startswith("sqlite:")

# 🚀 CORREÇÃO 2: Refatoração do bootstrap_database para garantir colunas ausentes
def bootstrap_database():
    """Cria tabelas e garante colunas necessárias."""
    with app.app_context():
        db.create_all()
        eng = db.engine
        insp = inspect(eng)
        
        # Função interna para adicionar uma coluna, se ausente
        def add_column_if_missing(table_name, column_name, column_type):
            try:
                # Obter colunas existentes na tabela
                cols = [c["name"] for c in insp.get_columns(table_name)]
            except Exception:
                # Tabela não existe, ignora, pois db.create_all() cuidou.
                return 

            if column_name not in cols:
                print(f"Adicionando coluna {column_name} à tabela {table_name}")
                try:
                    # Lógica para adicionar coluna usando ALTER TABLE
                    if is_sqlite_uri(DATABASE_URL):
                        # SQLite (local)
                        sql_type = "TEXT" if column_type.startswith("VARCHAR") else "BOOLEAN"
                        eng.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {sql_type}"))
                    else:
                        # PostgreSQL (Render)
                        eng.execute(text(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {column_type}"))
                except Exception as e:
                    # Se falhar (ex: a coluna já foi adicionada por outro processo), apenas continua
                    print(f"Alerta: Falha ao adicionar coluna {column_name} em {table_name}. Causa: {e}")

        # 1. Tabela Doacoes
        # Garante 'telefone' (que estava na lógica anterior)
        add_column_if_missing("doacoes", "telefone", "VARCHAR(50)")
        # Garante 'deleted' (necessário no modelo Doacao)
        add_column_if_missing("doacoes", "deleted", "BOOLEAN DEFAULT FALSE")

        # 2. Tabela Voluntarios (SOLUÇÃO DIRETA PARA O ERRO UndefinedColumn)
        # Garante 'deleted' (necessário no modelo Voluntario)
        add_column_if_missing("voluntarios", "deleted", "BOOLEAN DEFAULT FALSE")
        
        # Você pode adicionar mais verificações aqui se necessário para outras colunas/tabelas

# Chama bootstrap no import (garante em Render e local)
bootstrap_database()


# ---------- AUTH ----------
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
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
    return jsonify({"ok": True}), 201


@app.route("/auth/register-admin", methods=["POST"])
def register_admin():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    token_env = os.environ.get("ADMIN_SETUP_TOKEN")
    token_req = (data.get("token") or "").strip()

    if not token_env:
        return jsonify({"ok": False, "erro": "ADMIN_SETUP_TOKEN não definido"}), 500
    if token_req != token_env:
        return jsonify({"ok": False, "erro": "Token inválido"}), 401

    nome = (data.get("nome") or "").strip()
    email = (data.get("email") or "").strip().lower()
    senha = data.get("senha")

    if not nome or not email or not senha:
        return jsonify({"ok": False, "erro": "nome, email e senha são obrigatórios"}), 400
    if not validar_email(email):
        return jsonify({"ok": False, "erro": "email inválido"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"ok": False, "erro": "e-mail já cadastrado"}), 409

    u = User(email=email, nome=nome)
    u.set_password(senha)
    db.session.add(u)
    db.session.commit()
    return jsonify({"ok": True, "admin": {"nome": u.nome, "email": u.email}}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    email = (data.get("email") or "").strip().lower()
    senha = data.get("senha")
    if not email or not senha:
        return jsonify({"ok": False, "erro": "email e senha obrigatórios"}), 400

    u = User.query.filter_by(email=email).first()
    if not u or not u.check_password(senha):
        return jsonify({"ok": False, "erro": "credenciais inválidas"}), 401

    token = create_access_token(
        identity=str(u.id),
        additional_claims={"email": u.email, "nome": u.nome}
    )
    return jsonify({"ok": True, "access_token": token}), 200


# ---------- Rotas públicas ----------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"ok": True, "mensagem": "API ASZN Digital - Doações & Voluntariado"})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "status": "up"})

@app.route("/health/db", methods=["GET"])
def health_db():
    # Rota de health check para o banco de dados
    try:
        eng = db.engine
        insp = inspect(eng)

        def cols_safe(tbl):
            try:
                return [c["name"] for c in insp.get_columns(tbl)]
            except Exception:
                return []

        try:
            v_count = db.session.query(Voluntario).count()
        except Exception:
            v_count = -1
        try:
            d_count = db.session.query(Doacao).count()
        except Exception:
            d_count = -1

        return jsonify({
            "ok": True,
            "engine": str(eng.url),
            "tables": insp.get_table_names(),
            "voluntarios_count": v_count,
            "doacoes_count": d_count,
            "voluntarios_cols": cols_safe("voluntarios"),
            "doacoes_cols": cols_safe("doacoes"),
        })
    except Exception as e:
        # Se falhar aqui, o erro 500 está relacionado a esta exceção
        return jsonify({"ok": False, "erro": str(e), "mensagem": "Falha ao conectar ou consultar o banco."}), 500


# ---------- Público: criação ----------
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


# ---------- ADMIN ----------
@app.route("/admin/doacoes", methods=["GET"])
@jwt_required()
def admin_list_doacoes():
    q = Doacao.query.filter_by(deleted=False).order_by(Doacao.criado_em.desc()).limit(200).all()
    return jsonify({"ok": True, "doacoes": [to_dict(x) for x in q]})


@app.route("/admin/doacoes/<int:id>", methods=["DELETE"])
@jwt_required()
def admin_soft_delete_doacao(id):
    d = Doacao.query.get(id)
    if not d:
        return jsonify({"ok": False, "erro": "doação não encontrada"}), 404
    d.deleted = True
    db.session.commit()
    return jsonify({"ok": True, "mensagem": "soft deleted"})


@app.route("/admin/doacoes/<int:id>/restore", methods=["PATCH"])
@jwt_required()
def admin_restore_doacao(id):
    d = Doacao.query.get(id)
    if not d:
        return jsonify({"ok": False, "erro": "doação não encontrada"}), 404
    d.deleted = False
    db.session.commit()
    return jsonify({"ok": True, "mensagem": "restaurada"})


@app.route("/admin/voluntarios", methods=["GET"])
@jwt_required()
def admin_list_voluntarios():
    q = Voluntario.query.filter_by(deleted=False).order_by(Voluntario.criado_em.desc()).limit(200).all()
    return jsonify({"ok": True, "voluntarios": [to_dict(x) for x in q]})


@app.route("/admin/voluntarios/<int:id>", methods=["DELETE"])
@jwt_required()
def admin_soft_delete_voluntario(id):
    v = Voluntario.query.get(id)
    if not v:
        return jsonify({"ok": False, "erro": "voluntário não encontrado"}), 404
    v.deleted = True
    db.session.commit()
    return jsonify({"ok": True, "mensagem": "soft deleted"})


@app.route("/admin/voluntarios/<int:id>/restore", methods=["PATCH"])
@jwt_required()
def admin_restore_voluntario(id):
    v = Voluntario.query.get(id)
    if not v:
        return jsonify({"ok": False, "erro": "voluntário não encontrado"}), 404
    v.deleted = False
    db.session.commit()
    return jsonify({"ok": True, "mensagem": "restaurado"})


# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)