from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask import flash
import sqlite3
import bcrypt
import os
import time
from werkzeug.utils import secure_filename
from functools import wraps
from flask import get_flashed_messages
import re  # Para validação de e-mail e telefone


# Uma boa extensão do Flask para criptografia é o Flask-SQLAlchemy
# pip install Flask-SQLAlchemy (como instalar)
# from flask_sqlalchemy import SQLAlchemy (como importar)

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-key-not-secure'  # Use environment variable in production

# Configurações para upload de imagens
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Função para verificar extensão do arquivo
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Decorator para rotas que requerem login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, faça login para acessar esta página.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator para rotas que requerem privilégios de admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('user_admin'):
            flash("Acesso restrito a administradores.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def conectar_db():
    conn = None
    try:
        conn = sqlite3.connect("chefabook.db", check_same_thread=False)
        conn.row_factory = sqlite3.Row  # Para retornar dicionários em vez de tuplas
    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
    return conn

#Nessa parte ele verifica o formato da imagem enviada e verifica se é compativel
def verificar_coluna_imagem():
    with conectar_db() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(receitas)")
        colunas = [col[1] for col in cursor.fetchall()]
        
        if 'imagem' not in colunas:
            try:
                cursor.execute("ALTER TABLE receitas ADD COLUMN imagem BLOB")
                conn.commit()
                print("Coluna 'imagem' adicionada com sucesso")
            except Exception as e:
                print(f"Erro ao adicionar coluna: {e}")

# Função para criar tabelas no banco de dados
def criar_tabelas():
    with conectar_db() as conn:
        cursor = conn.cursor()
        # Tabela de usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                telefone TEXT,
                senha TEXT NOT NULL,
                admin INTEGER DEFAULT 0
            )
        ''')
        # Tabela de receitas (agora com campo para imagem)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS receitas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                categoria TEXT NOT NULL,
                ingredientes TEXT NOT NULL,
                preparo TEXT NOT NULL,
                imagem BLOB,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES usuarios(id)
            )
        ''')
        conn.commit()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/cadastrar_usuario', methods=['GET', 'POST'])
def cadastrar_usuario():
    if request.method == 'POST':
        try:
            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip().lower()
            telefone = request.form.get('telefone', '').strip()
            senha = request.form.get('senha', '').strip()
            confirmar_senha = request.form.get('confirmar_senha', '').strip()

            # Validação do Nome (obrigatório)
            if not nome:
                flash("O nome é obrigatório", "error")
                return render_template('cadastrar_usuario.html')

            # Validação do E-mail (formato válido)
            if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                flash("Por favor, insira um e-mail válido.", "error")
                return render_template('cadastrar_usuario.html')

            # Validação do Telefone (pelo menos 10 dígitos)
            telefone_limpo = re.sub(r'\D', '', telefone)
            if len(telefone_limpo) < 10 or len(telefone_limpo) > 11:
                flash("Telefone inválido. Insira DDD + número (10 ou 11 dígitos).", "error")
                return render_template('cadastrar_usuario.html')

            # Validação da Senha (apenas tamanho mínimo)
            if len(senha) < 6:
                flash("A senha deve ter pelo menos 6 caracteres", "error")
                return render_template('cadastrar_usuario.html')

            # Confirmação de Senha
            if senha != confirmar_senha:
                flash("As senhas não coincidem. Digite novamente.", "error")
                return render_template('cadastrar_usuario.html')

            # Verificar se o e-mail já existe
            conn = conectar_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
            if cursor.fetchone():
                flash("Este e-mail já está cadastrado. Use outro ou faça login.", "error")
                conn.close()
                return render_template('cadastrar_usuario.html')

            # Hash da senha (com bcrypt)
            hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Inserir usuário no banco
            cursor.execute('''
                INSERT INTO usuarios (nome, email, telefone, senha)
                VALUES (?, ?, ?, ?)
            ''', (nome, email, telefone_limpo, hashed_senha))
            conn.commit()
            conn.close()

            flash("Cadastro realizado com sucesso! Faça login.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Erro no cadastro: {str(e)}", "error")
            return render_template('cadastrar_usuario.html')

    return render_template('cadastrar_usuario.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '').strip()

        # Validação básica dos campos
        if not email or '@' not in email:
            flash("Por favor, insira um e-mail válido", "error")
            return render_template('login.html')
        
        if not senha:
            flash("Por favor, insira sua senha", "error")
            return render_template('login.html')

        conn = conectar_db()
        if conn is not None:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, senha, admin FROM usuarios WHERE email = ?", (email,))
                usuario = cursor.fetchone()
                
                if not usuario:
                    flash("E-mail não encontrado. Verifique ou cadastre-se.", "error")
                else:
                    # Verificação da senha com bcrypt
                    senha_db = usuario['senha'].encode('utf-8') if isinstance(usuario['senha'], str) else usuario['senha']
                    if bcrypt.checkpw(senha.encode('utf-8'), senha_db):
                        session['user_id'] = usuario['id']
                        session['user_nome'] = usuario['nome']
                        session['user_admin'] = bool(usuario['admin'])
                        flash("Login realizado com sucesso!", "success")
                        return redirect(url_for('dashboard'))
                    else:
                        flash("Senha incorreta. Tente novamente.", "error")
                    
            except Exception as e:
                flash(f"Erro no login: {str(e)}", "error")
            finally:
                conn.close()
    
    return render_template('login.html')



#Função para sair 
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "success")
    return redirect(url_for('login'))


#Função para voltar para home
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')




# Essa será a parte referente a parte de cadastrar_receitas, visualizar_receitas, atualizar_receitas e excluir_receitas.
# Nessa parte aqui vou tentar colocar também uma função para cadastrar uma imagem na receita.
# Rota para cadastro de receitas (agora com upload de imagem)
@app.route('/cadastrar_receita', methods=['GET', 'POST'])
@login_required
def cadastrar_receita():
    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        categoria = request.form.get('categoria', '').strip()
        ingredientes = request.form.get('ingredientes', '').strip()
        preparo = request.form.get('preparo', '').strip()
        user_id = session['user_id']
        
        # Verifica se foi enviado um arquivo de imagem
        if 'imagem' not in request.files:
            flash("Nenhuma imagem enviada", "error")
            return redirect(request.url)
        
        file = request.files['imagem']
        
        if file.filename == '':
            flash("Nenhuma imagem selecionada", "error")
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                imagem_bytes = file.read()
                
                with conectar_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO receitas 
                        (titulo, categoria, ingredientes, preparo, imagem, user_id) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (titulo, categoria, ingredientes, preparo, imagem_bytes, user_id))
                    conn.commit()
                
                flash("Receita cadastrada com sucesso!", "success")
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash(f"Erro ao cadastrar receita: {str(e)}", "error")
        else:
            flash("Tipo de arquivo não permitido", "error")

    return render_template('cadastrar_receitas.html')



# Rota para visualizar receitas (agora com exibição de imagem)
@app.route('/visualizar_receitas')
@login_required
def visualizar_receitas():
    conn = conectar_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, titulo, categoria, ingredientes, preparo, user_id, imagem 
                FROM receitas 
                WHERE user_id = ?
            ''', (session['user_id'],))
            
            receitas = []
            for row in cursor.fetchall():
                receita = {
                    'id': row['id'],
                    'titulo': row['titulo'],
                    'categoria': row['categoria'],
                    'ingredientes': row['ingredientes'],
                    'preparo': row['preparo'],
                    'user_id': row['user_id'],
                    'tem_imagem': row['imagem'] is not None  # Corrigido aqui
                }
                receitas.append(receita)

            return render_template('visualizar_receitas.html', receitas=receitas)
            
        except Exception as e:
            flash(f"Erro ao carregar receitas: {str(e)}", "error")
            return redirect(url_for('dashboard'))
        finally:
            conn.close()
    else:
        flash("Erro ao conectar ao banco de dados", "error")
        return redirect(url_for('dashboard'))
    

# Nessa parte o sistema ta chamando a imagem do banco de dados e esta exibindo.
# Rota para exibir imagem da receita
@app.route('/imagem_receita/<int:receita_id>')
@login_required
def imagem_receita(receita_id):
    conn = conectar_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT imagem FROM receitas 
                WHERE id = ? AND user_id = ?
            ''', (receita_id, session['user_id']))
            
            resultado = cursor.fetchone()
            
            if resultado and resultado['imagem']:
                response = make_response(resultado['imagem'])
                response.headers.set('Content-Type', 'image/jpeg')
                return response
            
        except Exception as e:
            print(f"Erro ao carregar imagem: {str(e)}")
        finally:
            conn.close()
    
    # Retorna uma imagem padrão se não encontrar
    from flask import send_from_directory
    return send_from_directory(app.static_folder, 'images/sem-imagem.jpg')

# Nessa parte o usuario vai poder editar a receitas nomo o nome o tipo imagem e etc.
# Rota para editar receita
@app.route('/editar_receita/<int:receita_id>', methods=['GET', 'POST'])
@login_required
def editar_receita(receita_id):
    conn = conectar_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            
            # Verifica se a receita pertence ao usuário
            cursor.execute("SELECT * FROM receitas WHERE id = ? AND user_id = ?", 
                         (receita_id, session['user_id']))
            receita = cursor.fetchone()
            
            if not receita:
                flash("Receita não encontrada ou você não tem permissão para editá-la", "error")
                return redirect(url_for('visualizar_receitas'))
            
            if request.method == 'POST':
                titulo = request.form.get('titulo', '').strip()
                categoria = request.form.get('categoria', '').strip()
                ingredientes = request.form.get('ingredientes', '').strip()
                preparo = request.form.get('preparo', '').strip()
                
                # Processamento da imagem
                imagem_bytes = receita['imagem']  # Mantém a imagem atual por padrão
                
                if 'imagem' in request.files:
                    file = request.files['imagem']
                    if file and file.filename != '' and allowed_file(file.filename):
                        imagem_bytes = file.read()

                # Atualiza a receita no banco de dados
                cursor.execute('''UPDATE receitas 
                                SET titulo = ?, categoria = ?, ingredientes = ?, preparo = ?, imagem = ?
                                WHERE id = ?''',
                                (titulo, categoria, ingredientes, preparo, imagem_bytes, receita_id))
                conn.commit()
                flash("Receita atualizada com sucesso!", "success")
                return redirect(url_for('visualizar_receitas'))
            
            return render_template('editar_receita.html', receita=receita)
            
        except Exception as e:
            flash(f"Erro ao editar receita: {e}", "error")
        finally:
            conn.close()
    
    return redirect(url_for('visualizar_receitas'))

# Nessa parte o usuario vai poder excluir a sua receita permanentimente.
# Rota para excluir receita
@app.route('/excluir_receita/<int:receita_id>', methods=['POST'])
@login_required
def excluir_receita(receita_id):
    conn = conectar_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            
            # Verifica se a receita pertence ao usuário
            cursor.execute("SELECT * FROM receitas WHERE id = ? AND user_id = ?", 
                         (receita_id, session['user_id']))
            receita = cursor.fetchone()
            
            if not receita:
                flash("Receita não encontrada ou você não tem permissão para excluí-la", "error")
                return redirect(url_for('visualizar_receitas'))
            
            # Exclui a receita do banco de dados
            cursor.execute("DELETE FROM receitas WHERE id = ?", (receita_id,))
            conn.commit()
            flash("Receita excluída com sucesso!", "success")
            
        except Exception as e:
            flash(f"Erro ao excluir receita: {e}", "error")
        finally:
            conn.close()
    
    return redirect(url_for('visualizar_receitas'))

@app.route("/login_adm")
def login_adm():
    return render_template("login_adm.html")



# Essa parte serve para o usuario colocar e passar pela verificação de login_adm
# Esses "admin@email.com e senha123" são para entrar no painel do administrador  
# Nessa parte da aplicação toda vez que tiver que adicionar um adm novo terá que mexer manualmente no codigo.
# Credenciais do Administrador
# Credenciais do Administrador (coloque no início do arquivo)
ADMIN_CREDENTIALS = {
    "email": "admin@email.com",
    "password": "senha123"
}

@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # Verifica as credenciais
        if email == ADMIN_CREDENTIALS["email"] and password == ADMIN_CREDENTIALS["password"]:
            # Configura a sessão do admin
            session['user_id'] = 0  # ID especial para admin
            session['user_admin'] = True
            session['user_nome'] = "Administrador"
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("painel_admin"))
        
        flash("Credenciais inválidas!", "error")
        return redirect(url_for("login_admin"))

    # Se for GET, mostra o formulário
    return render_template("login_admin.html")





# Nessa parte serão as funções que estão chamando no painel do administrador, 
# ele vai poder ver os usuarios, deleta-los, editar receitas e etc
# Verifica se o usuário logado é administrador

#Nessa parte o admin vai poder ver os usuarios seus dados.
@app.route("/painel_admin")
@admin_required
def painel_admin():
    with conectar_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, nome, email, telefone FROM usuarios")
        usuarios = cursor.fetchall()
        
        cursor.execute("SELECT * FROM receitas")
        receitas = cursor.fetchall()

    return render_template("painel_admin.html", usuarios=usuarios, receitas=receitas)

def verificar_admin():
    return session.get("user_admin") == True


# Nessa parte o admin vai poder ecluir os usuarios.
# Rota para excluir um usuário
@app.route("/excluir_usuario/<int:usuario_id>", methods=["POST"])
@admin_required
def excluir_usuario(usuario_id):
    try:
        with conectar_db() as conn:
            cursor = conn.cursor()
            # Primeiro exclui as receitas do usuário
            cursor.execute("DELETE FROM receitas WHERE user_id = ?", (usuario_id,))
            # Depois exclui o usuário
            cursor.execute("DELETE FROM usuarios WHERE id = ?", (usuario_id,))
            conn.commit()
        flash("Usuário e suas receitas excluídos com sucesso.", "success")
    except Exception as e:
        flash(f"Erro ao excluir usuário: {e}", "error")
    
    return redirect(url_for("painel_admin"))


# Nessa parte o admin vai poder excluir uma recita de certo usuario.
# Rota para excluir uma receita (pelo admin)
@app.route("/excluir_receita_admin/<int:receita_id>", methods=["POST"])
@admin_required
def excluir_receita_admin(receita_id):
    try:
        with conectar_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM receitas WHERE id = ?", (receita_id,))
            conn.commit()
        flash("Receita excluída com sucesso.", "success")
    except Exception as e:
        flash(f"Erro ao excluir receita: {e}", "error")
    
    return redirect(url_for("painel_admin"))


# Ocorre quando um usuário tenta acessar uma rota/URL que não está definida na sua aplicação
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    # Executa localmente com debug
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    criar_tabelas()
    verificar_coluna_imagem()
    app.run(debug=True)
else:
    # Executa no Render (sem debug)
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    criar_tabelas()
    verificar_coluna_imagem()


