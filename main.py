# Importação das bibliotecas necessárias
from flask import Flask, render_template, redirect, request, flash, url_for, session, send_from_directory, send_file
import fdb  # Biblioteca para conexão com banco de dados Firebird
from flask_bcrypt import generate_password_hash, check_password_hash  # Criptografia de senhas
#from fpdf import FPDF  # Geração de arquivos PDF (não utilizada neste código)

# Cria uma instância da aplicação Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  # Chave usada para proteger sessões e cookies

# Configuração da conexão com o banco de dados Firebird
host = 'localhost'
database = r'C:\Users\Aluno\Desktop\Ascender\ASCENDER.FDB'
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
        if not (maiuscula and minuscula and numero and caracterpcd):
            flash('A senha deve conter ao menos uma letra maiúscula, \numa minúscula, um número e um caractere especial.',
                  'danger')
            return redirect(url_for('cadastro'))

        # Verifica o tamanho da senha
        if len(senha) < 8 or len(senha) > 12:
            flash('A senha deve ter entre 8 e 12 caracteres.', 'danger')
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

                #  Redireciona Tipo 0 = admin, Tipo 2 = aluno
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
# LISTAR USUÁRIOS (VISÃO DO ADMIN)
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
    finally:
        cursor.close()

    return render_template('tabelaAlunos.html', alunos=alunos, qtd=qtd)





# -------------------------------------------------------
# ABRIR TABELA AULAS - inscreva-se
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
# ATIVAR / BLOQUEAR MODALIDADE
# -------------------------------------------------------
@app.route('/situacaoModalidade/<int:id>')
def situacaoModalidade(id):
    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca a situação atual do usuário (1 = ativo, 0 = bloqueado)
        cursor.execute("SELECT situacao FROM modalidade WHERE id_modalidade = ?", (id,))
        resultado = cursor.fetchone()

        if resultado:
            status_atual = resultado[0]

            # Troca o status: se estiver ativo, bloqueia; se estiver bloqueado, ativa
            if status_atual == 1:
                novo_status = 0
            else:
                novo_status = 1

            # Atualiza no banco
            cursor.execute("UPDATE modalidade SET situacao = ? WHERE id_modalidade = ?", (novo_status, id))
            con.commit()

    finally:
        cursor.close()

    return redirect(url_for('abrir_tabelamodalidade'))

# -------------------------------------------------------
# ABRIR TABELA AULA ADM
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
# CADASTRAR AULA
# -------------------------------------------------------
@app.route('/cadastroaula', methods=['GET', 'POST'])
def cadastroaula():
    print('incio')
    if 'id_usuario' not in session:
        return redirect(url_for('login'))


    # Coleta dados do formulário
    id_usuario = request.form['id_usuario']
    id_modalidade = request.form['id_modalidade']
    segunda = request.form['segunda']
    terca = request.form['terca']
    quarta = request.form['quarta']
    quinta = request.form['quinta']
    sexta = request.form['sexta']
    sabado = request.form['sabado']
    #dias_selecionados = request.form.getlist('dias')
    hora = request.form['hora']
    hora_fim = request.form['hora_fim']
    capacidade = request.form['capacidade']

    if not segunda:
        segunda = 0

    if not terca:
        terca = 0

    if not quarta:
        quarta = 0

    if not quinta:
        quinta = 0

    if not sexta:
        sexta= 0

    if not sabado:
        sabado = 0

    # Dias da semana - define como 1 se marcado, 0 se não

    cursor = con.cursor()

    try:  # tratamento de erro

        cursor.execute("SELECT id_usuario, tipo nome FROM usuarios WHERE tipo = 1 ")
        professores = cursor.fetchall()
        professor = cursor.fetchone()
        print(professores)
        print(professor)

        cursor.execute("SELECT id_modalidade, nome FROM modalidade")
        modalidades = cursor.fetchall()

        if request.method == 'POST':

            # Verifica se a aula já está cadastrado
            cursor.execute("""SELECT 1 FROM AULAS  
                               WHERE ID_USUARIO  =? AND ID_MODALIDADE  = ? AND SEGUNDA =? 
                                 AND TERCA =? AND QUARTA =? AND QUINTA =? AND SEXTA =? 
                                 AND SABADO =? AND HORA = ? AND HORA_FIM = ?""",
                           (id_usuario, id_modalidade, segunda, terca,
                            quarta, quinta, sexta, sabado, hora, hora_fim,))
            if cursor.fetchone():  # Verifica se a consulta retornou algum resultado
                flash('Essa aula já está cadastrada', 'error')
                return redirect(url_for('cadastroaula'))

            # Insere nova aula

            cursor.execute(
                            """ INSERT INTO aulas (id_usuario, id_modalidade, segunda, terca, quarta, 
                                                   quinta, sexta, sabado, hora, hora_fim, capacidade) 
                                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) """,
                                          (id_usuario, id_modalidade, segunda, terca, quarta,
                                            quinta, sexta, sabado, hora, hora_fim, capacidade)
                           )
            con.commit()
            flash('Aula cadastrada com sucesso!', 'success')
            return redirect(url_for('abrir_tabelaaulasadm', professores=professores, modalidades=modalidades))
        return render_template('cadastroAula.html')
    finally:
        cursor.close()


















# -------------------------------------------------------
# ABRIR TABELA PROFESSOR
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
# CADASTRAR PROFESSOR
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


        finally:

            cursor.close()

            flash('Professor cadastrada com sucesso!', 'success')

            return redirect(url_for('abrir_tabelaprofessores'))

    return render_template('cadastroProfessor.html')


# -------------------------------------------------------
# EDITAR PROFESSOR
# -------------------------------------------------------
@app.route('/editar_professor/<int:id>', methods=['GET', 'POST'])
def editar_professor(id):
    cursor = con.cursor()
    cursor.execute('SELECT id_usuario, nome, email, telefone, tipo, cpf FROM usuario WHERE id_usuario = ?', (id,))
    professor = cursor.fetchone()

    if not professor:
        cursor.close()
        flash("Usuário não foi encontrado")
        return redirect(url_for('cadastroprofessor'))

    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        cpf = request.form['cpf']
        telefone = request.form['telefone']

        # Atualiza os dados no banco
        cursor.execute(
            "UPDATE usuario SET nome = ?, email = ?, cpf = ?, telefone = ? WHERE id_usuario = ?",
            (nome, email, cpf, telefone, id)
        )
        con.commit()
        cursor.close()


        # Redireciona conforme o tipo de usuário
        if session['usuario'][5] == 0:
            return redirect(url_for('abrir_tabelaprofessores', id=professor[0]))

    return render_template('editarProfessor.html', professor=professor)




# -------------------------------------------------------
# ABRIR TABELA Modalidade
# -------------------------------------------------------
@app.route('/abrir_tabelamodalidade')
def abrir_tabelamodalidade():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("SELECT id_modalidade, nome, situacao FROM modalidade")
        modalidades= cursor.fetchall()
    finally:
        cursor.close()

    return render_template('tabelaModalidade.html', modalidades=modalidades)


# -------------------------------------------------------
# CADASTRO DE MODALIDADE
# -------------------------------------------------------
@app.route('/cadastromodalidade', methods=['GET', 'POST'])
def cadastromodalidade():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        nome = request.form['nome']
        cursor = con.cursor()
        try:
            cursor.execute("SELECT 1 FROM modalidade WHERE nome = ?", (nome,))
            if cursor.fetchone():
                flash('Essa modalidade já está cadastrada!', 'error')
                return redirect(url_for('cadastromodalidade'))

            cursor.execute(
                "INSERT INTO modalidade (nome) VALUES (?)", (nome,))
            con.commit()

        finally:
            cursor.close()
            flash('Modalidade cadastrada com sucesso!', 'success')
            return redirect(url_for('abrir_tabelamodalidade'))

    return render_template('cadastroModalidade.html')

# -------------------------------------------------------
# EDITAR MODALIDADE
# -------------------------------------------------------
@app.route('/editar_modalidade/<int:id>', methods=['GET', 'POST'])
def editar_modalidade(id):
    cursor = con.cursor()
    cursor.execute('SELECT id_modalidade, nome FROM modalidade', (id,))
    modalidade = cursor.fetchone()

    if not modalidade:
        cursor.close()
        flash("Modalidade não foi encontrado")
        return redirect(url_for('cadastromodalidade'))

    if request.method == 'POST':
        nome = request.form['nome']

        # Atualiza os dados no banco
        cursor.execute(
            "UPDATE modalidade SET nome = ? where id_modalidade = ?",
            (nome, id)
        )
        con.commit()
        cursor.close()


        # Redireciona conforme o tipo de usuário
        if session['usuario'][5] == 0:
            return redirect(url_for('abrir_tabelamodalidade'))

    return render_template('editarModalidade.html', modalidade=modalidade)


# -------------------------------------------------------
# DELETAR MODALIDADE
# -------------------------------------------------------
@app.route('/deletar/<int:id>', methods=('POST',))
def deletar(id):
    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))


    cursor = con.cursor()
    try:
        cursor.execute('DELETE FROM modalidade WHERE id_modalidade = ?', (id,))
        con.commit()
        flash('Modalidade excluída com sucesso!', 'success')
    except Exception as e:
        con.rollback()
        flash('Erro ao excluir o livro.', 'error')
    finally:
        cursor.close()

    return redirect(url_for('abrir_tabelamodalidade'))



# -------------------------------------------------------
# EXECUÇÃO DA APLICAÇÃO
# -------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)# Importação das bibliotecas necessárias
from flask import Flask, render_template, redirect, request, flash, url_for, session, send_from_directory, send_file
import fdb  # Biblioteca para conexão com banco de dados Firebird
from flask_bcrypt import generate_password_hash, check_password_hash  # Criptografia de senhas
#from fpdf import FPDF  # Geração de arquivos PDF (não utilizada neste código)

# Cria uma instância da aplicação Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  # Chave usada para proteger sessões e cookies

# Configuração da conexão com o banco de dados Firebird
host = 'localhost'
database = r'C:\Users\Aluno\Desktop\Ascender\ASCENDER.FDB'
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
        if not (maiuscula and minuscula and numero and caracterpcd):
            flash('A senha deve conter ao menos uma letra maiúscula, \numa minúscula, um número e um caractere especial.',
                  'danger')
            return redirect(url_for('cadastro'))

        # Verifica o tamanho da senha
        if len(senha) < 8 or len(senha) > 12:
            flash('A senha deve ter entre 8 e 12 caracteres.', 'danger')
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

                #  Redireciona Tipo 0 = admin, Tipo 2 = aluno
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
# LISTAR USUÁRIOS (VISÃO DO ADMIN)
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
    finally:
        cursor.close()

    return render_template('tabelaAlunos.html', alunos=alunos, qtd=qtd)





# -------------------------------------------------------
# ABRIR TABELA AULAS - inscreva-se
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
# ATIVAR / BLOQUEAR MODALIDADE
# -------------------------------------------------------
@app.route('/situacaoModalidade/<int:id>')
def situacaoModalidade(id):
    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca a situação atual do usuário (1 = ativo, 0 = bloqueado)
        cursor.execute("SELECT situacao FROM modalidade WHERE id_modalidade = ?", (id,))
        resultado = cursor.fetchone()

        if resultado:
            status_atual = resultado[0]

            # Troca o status: se estiver ativo, bloqueia; se estiver bloqueado, ativa
            if status_atual == 1:
                novo_status = 0
            else:
                novo_status = 1

            # Atualiza no banco
            cursor.execute("UPDATE modalidade SET situacao = ? WHERE id_modalidade = ?", (novo_status, id))
            con.commit()

    finally:
        cursor.close()

    return redirect(url_for('abrir_tabelamodalidade'))

# -------------------------------------------------------
# ABRIR TABELA AULA ADM
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
# CADASTRAR AULA
# -------------------------------------------------------
@app.route('/cadastroaula', methods=['GET', 'POST'])
def cadastroaula():
    print('incio')
    if 'id_usuario' not in session:
        return redirect(url_for('login'))


    # Coleta dados do formulário
    id_usuario = request.form['id_usuario']
    id_modalidade = request.form['id_modalidade']
    segunda = request.form['segunda']
    terca = request.form['terca']
    quarta = request.form['quarta']
    quinta = request.form['quinta']
    sexta = request.form['sexta']
    sabado = request.form['sabado']
    #dias_selecionados = request.form.getlist('dias')
    hora = request.form['hora']
    hora_fim = request.form['hora_fim']
    capacidade = request.form['capacidade']

    if not segunda:
        segunda = 0

    if not terca:
        terca = 0

    if not quarta:
        quarta = 0

    if not quinta:
        quinta = 0

    if not sexta:
        sexta= 0

    if not sabado:
        sabado = 0

    # Dias da semana - define como 1 se marcado, 0 se não

    cursor = con.cursor()

    try:  # tratamento de erro

        cursor.execute("SELECT id_usuario, tipo nome FROM usuarios WHERE tipo = 1 ")
        professores = cursor.fetchall()
        professor = cursor.fetchone()
        print(professores)
        print(professor)

        cursor.execute("SELECT id_modalidade, nome FROM modalidade")
        modalidades = cursor.fetchall()

        if request.method == 'POST':

            # Verifica se a aula já está cadastrado
            cursor.execute("""SELECT 1 FROM AULAS  
                               WHERE ID_USUARIO  =? AND ID_MODALIDADE  = ? AND SEGUNDA =? 
                                 AND TERCA =? AND QUARTA =? AND QUINTA =? AND SEXTA =? 
                                 AND SABADO =? AND HORA = ? AND HORA_FIM = ?""",
                           (id_usuario, id_modalidade, segunda, terca,
                            quarta, quinta, sexta, sabado, hora, hora_fim,))
            if cursor.fetchone():  # Verifica se a consulta retornou algum resultado
                flash('Essa aula já está cadastrada', 'error')
                return redirect(url_for('cadastroaula'))

            # Insere nova aula

            cursor.execute(
                            """ INSERT INTO aulas (id_usuario, id_modalidade, segunda, terca, quarta, 
                                                   quinta, sexta, sabado, hora, hora_fim, capacidade) 
                                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) """,
                                          (id_usuario, id_modalidade, segunda, terca, quarta,
                                            quinta, sexta, sabado, hora, hora_fim, capacidade)
                           )
            con.commit()
            flash('Aula cadastrada com sucesso!', 'success')
            return redirect(url_for('abrir_tabelaaulasadm', professores=professores, modalidades=modalidades))
        return render_template('cadastroAula.html')
    finally:
        cursor.close()


















# -------------------------------------------------------
# ABRIR TABELA PROFESSOR
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
# CADASTRAR PROFESSOR
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


        finally:

            cursor.close()

            flash('Professor cadastrada com sucesso!', 'success')

            return redirect(url_for('abrir_tabelaprofessores'))

    return render_template('cadastroProfessor.html')


# -------------------------------------------------------
# EDITAR PROFESSOR
# -------------------------------------------------------
@app.route('/editar_professor/<int:id>', methods=['GET', 'POST'])
def editar_professor(id):
    cursor = con.cursor()
    cursor.execute('SELECT id_usuario, nome, email, telefone, tipo, cpf FROM usuario WHERE id_usuario = ?', (id,))
    professor = cursor.fetchone()

    if not professor:
        cursor.close()
        flash("Usuário não foi encontrado")
        return redirect(url_for('cadastroprofessor'))

    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        cpf = request.form['cpf']
        telefone = request.form['telefone']

        # Atualiza os dados no banco
        cursor.execute(
            "UPDATE usuario SET nome = ?, email = ?, cpf = ?, telefone = ? WHERE id_usuario = ?",
            (nome, email, cpf, telefone, id)
        )
        con.commit()
        cursor.close()


        # Redireciona conforme o tipo de usuário
        if session['usuario'][5] == 0:
            return redirect(url_for('abrir_tabelaprofessores', id=professor[0]))

    return render_template('editarProfessor.html', professor=professor)




# -------------------------------------------------------
# ABRIR TABELA Modalidade
# -------------------------------------------------------
@app.route('/abrir_tabelamodalidade')
def abrir_tabelamodalidade():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("SELECT id_modalidade, nome, situacao FROM modalidade")
        modalidades= cursor.fetchall()
    finally:
        cursor.close()

    return render_template('tabelaModalidade.html', modalidades=modalidades)


# -------------------------------------------------------
# CADASTRO DE MODALIDADE
# -------------------------------------------------------
@app.route('/cadastromodalidade', methods=['GET', 'POST'])
def cadastromodalidade():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        nome = request.form['nome']
        cursor = con.cursor()
        try:
            cursor.execute("SELECT 1 FROM modalidade WHERE nome = ?", (nome,))
            if cursor.fetchone():
                flash('Essa modalidade já está cadastrada!', 'error')
                return redirect(url_for('cadastromodalidade'))

            cursor.execute(
                "INSERT INTO modalidade (nome) VALUES (?)", (nome,))
            con.commit()

        finally:
            cursor.close()
            flash('Modalidade cadastrada com sucesso!', 'success')
            return redirect(url_for('abrir_tabelamodalidade'))

    return render_template('cadastroModalidade.html')

# -------------------------------------------------------
# EDITAR MODALIDADE
# -------------------------------------------------------
@app.route('/editar_modalidade/<int:id>', methods=['GET', 'POST'])
def editar_modalidade(id):
    cursor = con.cursor()
    cursor.execute('SELECT id_modalidade, nome FROM modalidade', (id,))
    modalidade = cursor.fetchone()

    if not modalidade:
        cursor.close()
        flash("Modalidade não foi encontrado")
        return redirect(url_for('cadastromodalidade'))

    if request.method == 'POST':
        nome = request.form['nome']

        # Atualiza os dados no banco
        cursor.execute(
            "UPDATE modalidade SET nome = ? where id_modalidade = ?",
            (nome, id)
        )
        con.commit()
        cursor.close()


        # Redireciona conforme o tipo de usuário
        if session['usuario'][5] == 0:
            return redirect(url_for('abrir_tabelamodalidade'))

    return render_template('editarModalidade.html', modalidade=modalidade)


# -------------------------------------------------------
# DELETAR MODALIDADE
# -------------------------------------------------------
@app.route('/deletar/<int:id>', methods=('POST',))
def deletar(id):
    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))


    cursor = con.cursor()
    try:
        cursor.execute('DELETE FROM modalidade WHERE id_modalidade = ?', (id,))
        con.commit()
        flash('Modalidade excluída com sucesso!', 'success')
    except Exception as e:
        con.rollback()
        flash('Erro ao excluir o livro.', 'error')
    finally:
        cursor.close()

    return redirect(url_for('abrir_tabelamodalidade'))



# -------------------------------------------------------
# EXECUÇÃO DA APLICAÇÃO
# -------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)