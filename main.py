# Importação das bibliotecas necessárias
from flask import Flask, render_template, redirect, request, flash, url_for, session, send_from_directory, send_file
import fdb  # Biblioteca para conexão com banco de dados Firebird
from flask_bcrypt import generate_password_hash, check_password_hash  # Criptografia de senhas
from fpdf import FPDF  # Geração de arquivos PDF (não utilizada neste código)

# Cria uma instância da aplicação Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  # Chave usada para proteger sessões e cookies

# Configuração da conexão com o banco de dados Firebird
host = 'localhost'
database = r'C:\Users\Aluno\Desktop\ASCENDER.FDB'
user = 'sysdba'
password = 'sysdba'

# Conexão com o banco
con = fdb.connect(user=user, password=password, host=host, database=database)

# -------------------------------------------------------
# ROTA INICIAL
# -------------------------------------------------------
@app.route('/')
def index():
    return render_template('home.html')  # Renderiza a página inicial

# -------------------------------------------------------
# LOGIN
# -------------------------------------------------------
@app.route('/abrir_login')
def abrir_login():
    # Se o usuário não estiver logado, redireciona para o login
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

# -------------------------------------------------------
# DASHBOARD ADMINISTRADOR
# -------------------------------------------------------
@app.route('/abrir_dashbordadm/<int:id>')
def abrir_dashbordadm(id):
    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Busca dados do usuário logado
    cursor = con.cursor()
    cursor.execute('select id_usuario, nome, email, telefone, cpf from usuario where id_usuario = ?', (id,))
    usuario = cursor.fetchone()
    return render_template('dashbord_adm.html', usuario=usuario)

# -------------------------------------------------------
# DASHBOARD ALUNO
# -------------------------------------------------------
@app.route('/abrir_dashbordaluno/<int:id>')
def abrir_dashbordaluno(id):
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    cursor.execute('select id_usuario, nome, email, telefone, cpf from usuario where id_usuario = ?', (id,))
    usuario = cursor.fetchone()
    return render_template('dashboardaluno.html', usuario=usuario)

# -------------------------------------------------------
# CADASTRO DE USUÁRIO
# -------------------------------------------------------
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        # Coleta dados do formulário
        nome = request.form['nome']
        email = request.form['email']
        cpf = request.form['cpf']
        telefone = request.form['telefone']
        senha = request.form['senha']
        confirma = request.form['confirma']

        # Verifica se as senhas coincidem
        if senha != confirma:
            flash("Senhas não coincidem!")
            return redirect(url_for('cadastro'))

        # Verifica o tamanho da senha
        if len(senha) < 8 or len(senha) > 12:
            flash('A senha deve ter entre 8 e 12 caracteres.', 'danger')
            return redirect(url_for('cadastro'))

        # Verifica a complexidade da senha
        maiuscula = minuscula = numero = caracterpcd = False
        for s in senha:
            if s.isupper():
                maiuscula = True
            if s.islower():
                minuscula = True
            if s.isdigit():
                numero = True
            if not s.isalnum():
                caracterpcd = True

        # Se não atender aos critérios, bloqueia o cadastro
        if not (maiuscula or minuscula or numero or caracterpcd):
            flash('A senha deve conter ao menos uma letra maiúscula, uma minúscula, um número e um caractere especial.', 'danger')
            return redirect(url_for('cadastro'))

        # Criptografa a senha
        senha_cripto = generate_password_hash(senha).decode('utf-8')

        # Conecta ao banco e insere o novo usuário
        cursor = con.cursor()
        try: #tratamento de erro
            # Verifica se o e-mail já está cadastrado
            cursor.execute("SELECT 1 FROM usuario WHERE email = ?", (email,))
            if cursor.fetchone(): # Verifica se a consulta retornou algum resultado
                flash('Esse e-mail já está cadastrado!', 'error')
                return redirect(url_for('cadastro'))

            # Insere novo usuário (tipo = 2 → aluno)
            cursor.execute(
                "INSERT INTO usuario (tipo, nome, email, cpf, telefone, senha, situacao, tentativas) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (2, nome, email, cpf, telefone, senha_cripto, 0, 0)
            )
            con.commit()
        finally:
            cursor.close()

        flash('Usuário cadastrado com sucesso!', 'success')
        return render_template('login.html', aluno=nome)

    return render_template('cadastro.html')

# -------------------------------------------------------
# LOGIN DO USUÁRIO
# -------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        cursor = con.cursor()
        try:
            # Busca o usuário pelo e-mail
            cursor.execute("SELECT senha, id_usuario, nome, situacao, tentativas, tipo FROM usuario WHERE email = ?", (email,))
            usuario = cursor.fetchone() # Verifica se a consulta retornou algum resultado

            if not usuario:
                flash('Usuário não encontrado.', 'error')
                return redirect(url_for('login'))


            # Se o usuário está inativo, bloqueia o login
            if usuario[3] == 1:
                flash('Usuário está inativo. Contate o administrador.', 'error')
                return redirect(url_for('login'))

            # Se a senha está correta
            if usuario and check_password_hash(usuario[0], senha):
                cursor.execute("UPDATE usuario SET tentativas = 0 WHERE id_usuario = ?", (usuario[1],))
                session['id_usuario'] = usuario[1]
                session['usuario'] = usuario
                con.commit()

                # Tipo 0 = admin, Tipo 2 = aluno
                if usuario[5] == 0:
                    return redirect(url_for('abrir_dashbordadm', id=usuario[1]))
                return redirect(url_for('abrir_dashbordaluno', id=usuario[1]))

            # Se errou senha (conta aluno), incrementa tentativas
            if usuario[4] < 2 and usuario[5] != 0:
                cursor.execute("UPDATE usuario SET tentativas = tentativas + 1 WHERE id_usuario = ?", (usuario[1],))
                con.commit()

            # Bloqueia conta após 3 tentativas
            if usuario[4] == 2 and usuario[5] != 0:
                cursor.execute("UPDATE usuario SET tentativas = 3, situacao = 1 WHERE id_usuario = ?", (usuario[1],))
                con.commit()
                flash("Conta bloqueada após 3 tentativas. Contate o administrador.", "error")

            flash('E-mail ou senha incorretos. Tente novamente.', 'error')
            return redirect(url_for('login'))
        finally:
            cursor.close()

    return render_template('login.html')



# -------------------------------------------------------
# LOGOUT
# -------------------------------------------------------
@app.route('/logout')
def logout():
    session.pop("id_usuario", None)
    session.pop("usuario", None)# Remove o ID do usuário da sessão
    return redirect(url_for('index'))

# -------------------------------------------------------
# EDITAR USUÁRIO
# -------------------------------------------------------
@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    cursor = con.cursor()
    cursor.execute('SELECT id_usuario, nome, email, senha, telefone, tipo, cpf FROM usuario WHERE id_usuario = ?', (id,))
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        flash("Usuário não foi encontrado")
        return redirect(url_for('cadastro'))

    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        cpf = request.form['cpf']
        telefone = request.form['telefone']

        # Se o campo senha for preenchido, criptografa a nova senha
        if senha:
            senha_cripto = generate_password_hash(senha).decode('utf-8')
        else:
            senha_cripto = usuario[3]  # Mantém a senha antiga

        # Atualiza os dados no banco
        cursor.execute(
            "UPDATE usuario SET nome = ?, email = ?, senha = ?, cpf = ?, telefone = ? WHERE id_usuario = ?",
            (nome, email, senha_cripto, cpf, telefone, id)
        )
        con.commit()
        cursor.close()


        # Redireciona conforme o tipo de usuário
        if session['usuario'][5] == 0:
            return redirect(url_for('ver_alunos', id=usuario[0]))
        else:
            return redirect(url_for('abrir_dashbordaluno', id=usuario[0]))

    return render_template('editaraluno.html', usuario=usuario)

# -------------------------------------------------------
# LISTAR ALUNOS (VISÃO DO ADMIN)
# -------------------------------------------------------
@app.route('/ver_alunos')
def ver_alunos():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("SELECT id_usuario, nome, email, telefone, cpf, situacao FROM usuario WHERE tipo = 2")
        alunos = cursor.fetchall()
        qtd = len(alunos)
        print(qtd)
    finally:
        cursor.close()

    return render_template('tabelaAlunos.html', alunos=alunos, qtd=qtd)

# -------------------------------------------------------
# ATIVAR / BLOQUEAR USUÁRIO
# -------------------------------------------------------
@app.route('/situacao/<int:id>')
def situacao(id):
    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca a situação atual do usuário (1 = ativo, 0 = bloqueado)
        cursor.execute("SELECT situacao FROM usuario WHERE id_usuario = ?", (id,))
        resultado = cursor.fetchone()

        if resultado:
            status_atual = resultado[0]

            # Troca o status: se estiver ativo, bloqueia; se estiver bloqueado, ativa
            if status_atual == 1:
                novo_status = 0
            else:
                novo_status = 1

            # Atualiza no banco
            cursor.execute("UPDATE usuario SET situacao = ? WHERE id_usuario = ?", (novo_status, id))
            con.commit()

    finally:
        cursor.close()

    return redirect(url_for('ver_alunos'))

# -------------------------------------------------------
# Inscreva-se
# -------------------------------------------------------
@app.route('/abrir_tabelaaulas')
def abrir_tabelaaulas():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("SELECT id_aulas, id_usuario, id_modalidade, capacidade, hora, segunda, terca, quarta, quinta, sexta, sabado FROM aulas WHERE id_usuario = ?",
                       (session['id_usuario'],))
        aulas = cursor.fetchall()
    finally:
        cursor.close()

    return render_template('tabelaAulas.html', aulas=aulas)



# -------------------------------------------------------
# Tabela Aula Adm
# -------------------------------------------------------
@app.route('/abrir_tabelaaulasadm')
def abrir_tabelaaulasadm():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("SELECT id_aulas, id_usuario, id_modalidade, capacidade, hora, segunda, terca, quarta, quinta, sexta, sabado FROM aulas WHERE id_usuario = ?",
                       (session['id_usuario'],))
        aulas = cursor.fetchall()
    finally:
        cursor.close()

    return render_template('tabelaAulaAdm.html', aulas=aulas)


# -------------------------------------------------------
# Tabela Modalidade
# -------------------------------------------------------
@app.route('/abrir_tabelamodalidade')
def abrir_tabelamodalidade():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("SELECT id_modalidade, nome FROM modalidade WHERE id_modalidade = ?",
                       (session['id_usuario'],))
        modalidade= cursor.fetchall()
    finally:
        cursor.close()

    return render_template('tabelaModalidade.html', modalidade=modalidade)

# -------------------------------------------------------
# Tabela professores
# -------------------------------------------------------
@app.route('/abrir_tabelaprofessores')
def abrir_tabelaprofessores():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("SELECT id_usuario, nome, email, telefone, cpf, situacao FROM usuario WHERE tipo = 1")
        professor = cursor.fetchall()
    finally:
        cursor.close()

    return render_template('tabelaProfessores.html', professor=professor)


# -------------------------------------------------------
# CADASTRO DE AULA
# -------------------------------------------------------
@app.route('/cadastroprofessor', methods=['GET', 'POST'])
def cadastroprofessor():
    print()
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Coleta dados do formulário
        nome = request.form['nome']
        email = request.form['email']
        cpf = request.form['cpf']
        telefone = request.form['telefone']
        cursor = con.cursor()
        try:  # tratamento de erro
            # Verifica se o e-mail já está cadastrado
            cursor.execute("SELECT 1 FROM usuario WHERE email = ?", (email,))
            if cursor.fetchone():  # Verifica se a consulta retornou algum resultado
                flash('Esse e-mail já está cadastrado!', 'error')
                return redirect(url_for('cadastroprofessor'))

            # Insere novo usuário (tipo = 2 → aluno)
            cursor.execute(
                "INSERT INTO usuario (tipo, nome, email, cpf, telefone) VALUES (?, ?, ?, ?, ?)",
                (1, nome, email, cpf, telefone)
            )
            con.commit()
            usuario = session['id_usuario']
            flash('Professor cadastrado com sucesso!', 'success')
            return render_template('dashbord_adm.html', usuario=usuario)

        finally:
            cursor.close()

    return render_template('cadastroProfessor.html')

# -------------------------------------------------------
# EXECUÇÃO DA APLICAÇÃO
# -------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
