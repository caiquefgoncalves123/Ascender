from flask import Flask, render_template, redirect, request, flash, url_for, session, send_from_directory, send_file
from datetime import datetime
import fdb  # Biblioteca para conexão com banco de dados Firebird
from flask_bcrypt import generate_password_hash, check_password_hash  # Criptografia de senhas
from fpdf import FPDF  # Geração de arquivos PDF (não utilizada neste código)

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

    cursor.execute("SELECT id_usuario, tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
    tipo = cursor.fetchone()


    if tipo[1] == 2:
        flash('Acesso negado, você não é Administrador!')
        return redirect(url_for('login'))

    cursor.execute('select id_usuario, nome, email, telefone, cpf from usuario where id_usuario = ?', (id,))
    usuario = cursor.fetchone()
    # Contar alunos (tipo = 2)
    cursor.execute("SELECT COUNT(*) FROM usuario WHERE tipo = 2")
    total_alunos = cursor.fetchone()[0]

    # Contar professores (tipo = 1)
    cursor.execute("SELECT COUNT(*) FROM usuario WHERE tipo = 1")
    total_professores = cursor.fetchone()[0]

    # Contar modalidades ativas
    cursor.execute("SELECT COUNT(*) FROM modalidade WHERE COALESCE(situacao, 0) = 0")
    total_modalidades = cursor.fetchone()[0]

    # Contar aulas
    cursor.execute("SELECT COUNT(*) FROM aulas")
    total_aulas = cursor.fetchone()[0]


    return render_template('dashbord_adm.html', usuario=usuario, total_alunos=total_alunos,
                             total_professores=total_professores,
                             total_modalidades=total_modalidades,
                             total_aulas=total_aulas)

# -------------------------------------------------------
# DASHBOARD ALUNO
# -------------------------------------------------------
@app.route('/abrir_dashbordaluno/<int:id>')
def abrir_dashbordaluno(id):
    if 'id_usuario' not in session:
        return redirect(url_for('login'))


    cursor = con.cursor()
    cursor.execute('SELECT id_usuario, nome, email, telefone, cpf FROM usuario WHERE id_usuario = ?', (id,))
    usuario = cursor.fetchone()

    if usuario[0] != (id) :
        flash('Acesso negado, você não é Administrador!')
        return redirect(url_for('login'))

    # Buscar aulas em que o aluno está inscrito
    cursor.execute("""
        SELECT a.id_aulas, m.nome AS modalidade, u.nome AS professor, 
               a.hora, a.hora_fim,
               CASE a.segunda WHEN 1 THEN 'Seg ' ELSE '' END ||
               CASE a.terca WHEN 1 THEN 'Ter ' ELSE '' END ||
               CASE a.quarta WHEN 1 THEN 'Qua ' ELSE '' END ||
               CASE a.quinta WHEN 1 THEN 'Qui ' ELSE '' END ||
               CASE a.sexta WHEN 1 THEN 'Sex ' ELSE '' END ||
               CASE a.sabado WHEN 1 THEN 'Sab ' ELSE '' END AS dias_semana
        FROM aulas a
        INNER JOIN usuario u ON a.id_usuario = u.id_usuario
        INNER JOIN modalidade m ON a.id_modalidade = m.id_modalidade
        INNER JOIN AULAS_ALUNO aa ON aa.ID_AULAS = a.ID_AULAS
        WHERE aa.ID_USUARIO = ? AND aa.SITUACAO = 0
    """, (id,))
    aulas_inscritas = cursor.fetchall()

    cursor.close()

    return render_template('dashboardaluno.html', usuario=usuario, aulas_inscritas=aulas_inscritas)



# -------------------------------------------------------
# CADASTRO DE USUÁRIO
# -------------------------------------------------------
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        # Coleta dados do formulário
        nome = request.form['nome'].strip().capitalize()
        email = request.form['email'].strip().lower()
        cpf = request.form['cpf'].strip()
        telefone = request.form['telefone'].strip()
        senha = request.form['senha']
        confirma = request.form['confirma']

        # Verifica se as senhas coincidem
        if senha != confirma:
            flash("Senhas não coincidem!")
            return redirect(url_for('cadastro'))

        if not nome:
            flash("O nome não pode estar vazio.", "error")
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
            flash('A senha não está dentro dos parâmetros.',
                  'error')
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
                "INSERT INTO usuario (tipo, nome, email, cpf, telefone, senha, situacao, tentativas) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id_usuario",
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
        email = request.form['email'].lower()
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
        nome = request.form['nome'].strip().capitalize()
        email = request.form['email'].lower()
        senha = request.form['senha']
        cpf = request.form['cpf']
        telefone = request.form['telefone']

        # Verifica se o email já existe
        cursor.execute("SELECT 1 FROM usuario WHERE email = ? AND id_usuario != ?", (email, id))
        if cursor.fetchone():
            flash('Esse e-mail já está cadastrado!', 'error')
            return redirect(url_for('editar_usuario', id=id))

        # Validação da senha (se for preenchida)
        if senha:
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
                flash('A senha não está dentro dos parâmetros.',
                      'error')
                return redirect(url_for('editar_usuario', id=id))

            # Verifica o tamanho da senha
            if len(senha) < 8 or len(senha) > 12:
                flash('A senha deve ter entre 8 e 12 caracteres.', 'danger')
                return redirect(url_for('editar_usuario', id=id))

            # Criptografa a nova senha
            senha_cripto = generate_password_hash(senha).decode('utf-8')
        else:
            senha_cripto = usuario[3]  # Mantém a senha antiga se não for fornecida uma nova

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
# INSCREVER/CANCELAR AULA
# -------------------------------------------------------
@app.route('/situacao_aula/<int:id>')
def situacao_aula(id):
    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))
    cursor = con.cursor()
    try:

        # Busca a situação atual do usuário (1 = ativo, 0 = bloqueado)
        cursor.execute("SELECT situacao FROM aulas_aluno WHERE id_aulas = ?", (id,))
        resultado = cursor.fetchone()

        if resultado:
            status_atual = resultado[0]

            # Troca o status: se estiver ativo, bloqueia; se estiver bloqueado, ativa
            if status_atual == 1:
                novo_status = 0
            else:
                novo_status = 1

            # Atualiza no banco
            cursor.execute("UPDATE aulas_aluno SET situacao = ? WHERE id_aulas = ?", (novo_status, id))
            con.commit()

    finally:
        cursor.close()

    return redirect(url_for('abrir_tabelaaulasalunos'))


# -------------------------------------------------------
# LISTAR USUÁRIOS (VISÃO DO ADMIN)
# -------------------------------------------------------
@app.route('/ver_alunos')
def ver_alunos():
    if 'id_usuario' not in session:
        flash('Usuário não está logado')
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:

        cursor.execute("SELECT id_usuario, tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        tipo = cursor.fetchone()

        if tipo[1] == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))


        cursor.execute("SELECT id_usuario, tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        tipo = cursor.fetchone()


        if tipo[1] == 2:
            flash('Acesso Negado!')
            return redirect(url_for('login'))

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
        cursor.execute("SELECT id_usuario FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))


        cursor.execute("""SELECT a.id_aulas
                                     , u.nome AS professor
                                     , m.nome AS modalidade
                                     , a.capacidade
                                     , a.hora
                                     , a.hora_fim
                                    , CASE a.segunda
                                        WHEN 1 THEN 'Seg '
                                       ELSE '' 
                                       END  ||
                                          CASE a.terca
                                        WHEN 1 THEN 'Ter '
                                       ELSE '' 
                                       END ||
                                                 CASE a.quarta
                                        WHEN 1 THEN 'Qua '
                                       ELSE '' 
                                       END ||  
                                      CASE a.quinta
                                        WHEN 1 THEN 'Qui '
                                       ELSE '' 
                                       END ||
                                          CASE a.sexta
                                        WHEN 1 THEN 'Sex '
                                       ELSE '' 
                                       END ||
                                      CASE a.sabado
                                        WHEN 1 THEN 'Sab '
                                       ELSE '' 
                                       END AS dias_semana

                               FROM aulas a
                               INNER JOIN usuario u ON a.id_usuario = u.id_usuario
                               INNER JOIN modalidade m ON a.id_modalidade = m.id_modalidade
                           """)
        aulas = cursor.fetchall()



    finally:
        cursor.close()

    return render_template('tabelaAulaAdm.html', aulas=aulas)
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
        cursor.execute("SELECT id_usuario, tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        tipo = cursor.fetchone()

        if tipo[1] == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))

        cursor.execute("""
            SELECT 
                a.id_aulas,
                u.nome AS professor,
                m.nome AS modalidade,
                a.capacidade,
                a.hora,
                a.hora_fim,
                CASE a.segunda WHEN 1 THEN 'Seg ' ELSE '' END ||
                CASE a.terca WHEN 1 THEN 'Ter ' ELSE '' END ||
                CASE a.quarta WHEN 1 THEN 'Qua ' ELSE '' END ||
                CASE a.quinta WHEN 1 THEN 'Qui ' ELSE '' END ||
                CASE a.sexta WHEN 1 THEN 'Sex ' ELSE '' END ||
                CASE a.sabado WHEN 1 THEN 'Sab ' ELSE '' END AS dias_semana,

                a.capacidade || '/' || (
                    SELECT COUNT(*) 
                    FROM AULAS_ALUNO aa 
                    WHERE aa.ID_AULAS = a.id_aulas
                    AND aa.situacao = 0
                ) AS capacidade_ocupacao

            FROM aulas a
            INNER JOIN usuario u ON a.id_usuario = u.id_usuario
            INNER JOIN modalidade m ON a.id_modalidade = m.id_modalidade
        """)

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

    # Dias da semana - define como 1 se marcado, 0 se não

    cursor = con.cursor()

    try:  # tratamento de erro

        cursor.execute("SELECT id_usuario, tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        tipo = cursor.fetchone()

        if tipo[1] == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))

        cursor.execute("SELECT id_usuario, nome FROM usuario WHERE tipo = 1 ")
        professores = cursor.fetchall()

        cursor.execute("SELECT id_modalidade, nome FROM modalidade where coalesce(situacao, 0) = 0")
        modalidades = cursor.fetchall()


        if request.method == 'POST':

            # Coleta dados do formulário
            id_usuario = request.form['id_usuario']
            id_modalidade = request.form['id_modalidade']


            segunda = 1 if 'segunda' in request.form else 0
            terca = 1 if 'terca' in request.form else 0
            quarta = 1 if 'quarta' in request.form else 0
            quinta = 1 if 'quinta' in request.form else 0
            sexta = 1 if 'sexta' in request.form else 0
            sabado = 1 if 'sabado' in request.form else 0

            hora = request.form['hora']
            hora_fim = request.form['hora_fim']
            capacidade = request.form['capacidade']

            if hora > hora_fim:
                flash("O horário do fim precisa ser maior que o de início!")
                return redirect(url_for('cadastroaula'))


            if capacidade <= '0':
                flash("A capacidade precisa ser maior que 0!", 'error')
                return redirect(url_for('cadastroaula'))

            if not (segunda or terca or quarta or quinta or sexta or sabado):
                flash("Selecione pelo menos um dia da semana!", "error")
                return redirect(url_for('cadastroaula'))

            # Verifica se a aula já está cadastrado
            cursor.execute("""SELECT 1
                            FROM AULAS
                            WHERE ID_USUARIO = ?
                              AND ((SEGUNDA = 1 AND ? = 1) OR
                                    (TERCA   = 1 AND ?   = 1) OR
                                    (QUARTA  = 1 AND ?  = 1) OR
                                    (QUINTA  = 1 AND ?  = 1) OR
                                    (SEXTA   = 1 AND ?   = 1) OR
                                    (SABADO  = 1 AND ?  = 1))
                              AND ((? BETWEEN HORA AND HORA_FIM)
                                    OR (HORA BETWEEN ? AND ?)
                                    OR (? BETWEEN HORA AND HORA_FIM));
                            """,
                           (id_usuario, segunda, terca,
                            quarta, quinta, sexta, sabado,
                            hora, hora, hora_fim, hora_fim))
            if cursor.fetchone():  # Verifica se a consulta retornou algum resultado
                flash('Esse horário já está ocupado!', 'error')
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
        return render_template('cadastroAula.html', professores=professores, modalidades=modalidades)
    finally:
        cursor.close()



# -------------------------------------------------------
# ABRIR TABELA PROFESSOR
# -------------------------------------------------------
@app.route('/abrir_tabelaprofessores')
def abrir_tabelaprofessores():
    if 'id_usuario' not in session:
        flash('Usuário não está logado')
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca o tipo do usuário logado
        cursor.execute("SELECT tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        usuario = cursor.fetchone()

        if not usuario:
            flash('Usuário não encontrado!')
            return redirect(url_for('login'))

        tipo_usuario = usuario[0]  # Firebird retorna tupla (tipo,)

        # Verifica se é administrador
        if tipo_usuario == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))

        # Busca todos os professores (tipo = 1)
        cursor.execute("""
            SELECT id_usuario, nome, email, telefone, cpf, situacao
            FROM usuario
            WHERE tipo = 1
        """)
        professores = cursor.fetchall()

    finally:
        cursor.close()

    return render_template('tabelaProfessores.html', professor=professores)

# -------------------------------------------------------
# CADASTRAR PROFESSOR
# -------------------------------------------------------
@app.route('/cadastroprofessor', methods=['GET', 'POST'])
def cadastroprofessor():
    if 'id_usuario' not in session:
        flash('Usuário não está logado')
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca o tipo do usuário logado
        cursor.execute("SELECT tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        usuario = cursor.fetchone()

        if not usuario:
            flash('Usuário não encontrado!')
            return redirect(url_for('login'))

        tipo_usuario = usuario[0]  # Firebird retorna tupla (tipo,)

        # Verifica se é administrador
        if tipo_usuario == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))

        # Se o formulário foi enviado
        if request.method == 'POST':
            nome = request.form['nome'].strip().capitalize()
            email = request.form['email'].strip().lower()
            cpf = request.form['cpf'].strip()
            telefone = request.form['telefone'].strip()

            # Validação: nome não pode estar vazio
            if not nome:
                flash("O nome não pode estar vazio.", "error")
                return redirect(url_for('cadastroprofessor'))

            # Verifica se o e-mail já está cadastrado
            cursor.execute("SELECT 1 FROM usuario WHERE email = ?", (email,))
            if cursor.fetchone():
                flash('Esse e-mail já está cadastrado!', 'error')
                return redirect(url_for('cadastroprofessor'))

            # Cadastra novo professor (tipo = 1)
            cursor.execute("""
                INSERT INTO usuario (tipo, nome, email, cpf, telefone)
                VALUES (?, ?, ?, ?, ?) RETURNING ID_USUARIO
            """, (1, nome, email, cpf, telefone))
            id_usuario = cursor.fetchone()[0]
            con.commit()


            arquivo = request.files['arquivo']
            arquivo.save(f'static/uploads/foto{id_usuario}.jpg')

            flash('Professor cadastrado com sucesso!', 'success')
            return redirect(url_for('abrir_tabelaprofessores'))

    finally:
        cursor.close()

    return render_template('cadastroProfessor.html')


# -------------------------------------------------------
# EDITAR PROFESSOR
# -------------------------------------------------------
@app.route('/editar_professor/<int:id>', methods=['GET', F'POST'])
def editar_professor(id):
    cursor = con.cursor()
    cursor.execute("SELECT id_usuario, tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
    tipo = cursor.fetchone()

    if tipo[1] == 2:
        flash('Acesso negado, você não é Administrador!')
        return redirect(url_for('login'))

    cursor.execute('SELECT id_usuario, nome, email, telefone, tipo, cpf FROM usuario WHERE id_usuario = ?', (id,))
    professor = cursor.fetchone()

    if not professor:
        cursor.close()
        flash("Usuário não foi encontrado")
        return redirect(url_for('cadastroprofessor'))


    if request.method == 'POST':
        nome = request.form['nome'].capitalize().strip()
        email = request.form['email'].lower()
        cpf = request.form['cpf']
        telefone = request.form['telefone']

        if not nome:
            flash("O nome não pode estar vazio.", "error")
            return redirect(url_for('editar_professor', id=id))

        # Verifica se o email já existe
        cursor.execute("SELECT 1 FROM usuario WHERE email = ? AND id_usuario != ?", (email, id))
        if cursor.fetchone():
            flash('Esse e-mail já está cadastrado!', 'error')
            return redirect(url_for('editar_professor', id=id))

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
        flash('Usuário não está logado')
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca o tipo do usuário logado
        cursor.execute("SELECT tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        usuario = cursor.fetchone()

        if not usuario:
            flash('Usuário não encontrado!')
            return redirect(url_for('login'))

        tipo_usuario = usuario[0]  # Firebird retorna tupla (tipo,)

        # Verifica se é administrador
        if tipo_usuario == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))

        # Busca todas as modalidades
        cursor.execute("SELECT id_modalidade, nome, situacao FROM modalidade")
        modalidades = cursor.fetchall()

    finally:
        cursor.close()

    return render_template('tabelaModalidade.html', modalidades=modalidades)


# -------------------------------------------------------
# CADASTRO DE MODALIDADE
# -------------------------------------------------------
@app.route('/cadastromodalidade', methods=['GET', 'POST'])
def cadastromodalidade():
    if 'id_usuario' not in session:
        flash('Usuário não está logado')
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca o tipo do usuário logado
        cursor.execute("SELECT tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        usuario = cursor.fetchone()

        if not usuario:
            flash('Usuário não encontrado!')
            return redirect(url_for('login'))

        tipo_usuario = usuario[0]  # Firebird retorna tupla (tipo,)

        # Verifica se é administrador
        if tipo_usuario == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))

        # Se o formulário foi enviado
        if request.method == 'POST':
            nome = request.form['nome'].capitalize().strip()

            if not nome:
                flash("O nome não pode estar vazio.", "error")
                return redirect(url_for('cadastromodalidade'))

            # Verifica duplicidade
            cursor.execute("SELECT 1 FROM modalidade WHERE nome = ?", (nome,))
            if cursor.fetchone():
                flash('Essa modalidade já está cadastrada!', 'error')
                return redirect(url_for('cadastromodalidade'))

            # Cadastra nova modalidade
            cursor.execute("INSERT INTO modalidade (nome) VALUES (?)", (nome,))
            con.commit()

            flash('Modalidade cadastrada com sucesso!', 'success')
            return redirect(url_for('abrir_tabelamodalidade'))

    finally:
        cursor.close()

    # Renderiza o formulário
    return render_template('cadastroModalidade.html')

# -------------------------------------------------------
# EDITAR MODALIDADE
# -------------------------------------------------------
@app.route('/editar_modalidade/<int:id>', methods=['GET', 'POST'])
def editar_modalidade(id):
    if 'id_usuario' not in session:
        flash('Usuário não está logado')
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        # Busca o tipo do usuário logado
        cursor.execute("SELECT tipo FROM usuario WHERE id_usuario = ?", (session['id_usuario'],))
        usuario = cursor.fetchone()

        if not usuario:
            flash('Usuário não encontrado!')
            return redirect(url_for('login'))

        tipo_usuario = usuario[0]  # Firebird retorna tupla

        # Verifica se é administrador (só admins podem editar)
        if tipo_usuario == 2:
            flash('Acesso negado, você não é Administrador!')
            return redirect(url_for('login'))

        # Busca a modalidade que será editada
        cursor.execute("SELECT id_modalidade, nome FROM modalidade WHERE id_modalidade = ?", (id,))
        modalidade = cursor.fetchone()

        if not modalidade:
            flash("Modalidade não foi encontrada", "error")
            return redirect(url_for('cadastromodalidade'))

        # Se o formulário foi enviado
        if request.method == 'POST':
            nome = request.form['nome'].capitalize().strip()

            if not nome:
                flash("O nome não pode estar vazio.", "error")
                return redirect(url_for('editar_modalidade', id=id))

            # Verifica se já existe outra modalidade com o mesmo nome
            cursor.execute("""
                SELECT id_modalidade
                FROM modalidade
                WHERE nome = ? AND id_modalidade != ?
            """, (nome, id))
            existente = cursor.fetchone()

            if existente:
                flash('Essa modalidade já está cadastrada!', 'error')
                return redirect(url_for('editar_modalidade', id=id))

            # Atualiza a modalidade
            cursor.execute("""
                UPDATE modalidade
                SET nome = ?
                WHERE id_modalidade = ?
            """, (nome, id))
            con.commit()

            flash('Modalidade atualizada com sucesso!', 'success')
            return redirect(url_for('abrir_tabelamodalidade'))

    finally:
        cursor.close()

    # Renderiza o template de edição
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
        flash('Modalidade vinculada a uma aula.', 'error')
    finally:
        cursor.close()

    return redirect(url_for('abrir_tabelamodalidade'))


# -------------------------------------------------------
# ABRIR TABELA AULAS ALUNO
# -------------------------------------------------------
@app.route('/abrir_tabelaaulasalunos')
def abrir_tabelaaulasalunos():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()

    try:
        cursor.execute(""" 
            SELECT 
                a.id_aulas,
                u.nome AS professor,
                m.nome AS modalidade,
                a.capacidade,
                a.hora,
                a.hora_fim,
                CASE a.segunda WHEN 1 THEN 'Seg ' ELSE '' END ||
                CASE a.terca   WHEN 1 THEN 'Ter ' ELSE '' END ||
                CASE a.quarta  WHEN 1 THEN 'Qua ' ELSE '' END ||
                CASE a.quinta  WHEN 1 THEN 'Qui ' ELSE '' END ||
                CASE a.sexta   WHEN 1 THEN 'Sex ' ELSE '' END ||
                CASE a.sabado  WHEN 1 THEN 'Sab ' ELSE '' END AS dias_semana,
                a.CAPACIDADE || '/' || (
                    SELECT COUNT(*) 
                    FROM AULAS_ALUNO aa 
                    WHERE aa.ID_AULAS = a.id_aulas
                    AND aa.situacao = 0
                ) AS capacidade_ocupacao,
                1 AS SITUACAO
            FROM aulas a
            INNER JOIN usuario u ON a.id_usuario = u.id_usuario
            INNER JOIN modalidade m ON a.id_modalidade = m.id_modalidade
            WHERE 
                a.capacidade > (
                    SELECT COUNT(*) 
                    FROM AULAS_ALUNO aa 
                    WHERE aa.ID_AULAS = a.id_aulas
                    AND aa.situacao = 0
                )

        """, (id_usuario,))

        aulas = cursor.fetchall()
    finally:
        cursor.close()

    return render_template('tabelaAulas.html', aulas=aulas)


# -------------------------------------------------------
# Inscreva-se
# -------------------------------------------------------
@app.route('/inscrever/<int:id>', methods=['POST'])
def inscrever(id):
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    id_usuario = session['id_usuario']
    inscricao = request.form.get('inscricao')
    cursor = con.cursor()

    try:
        # Verificar se o usuário já está inscrito nesta aula
        cursor.execute("""
            SELECT SITUACAO 
            FROM AULAS_ALUNO 
            WHERE ID_AULAS = ? AND ID_USUARIO = ?
        """, (id, id_usuario))

        inscricao_existente = cursor.fetchone()

        # Converter para inteiro para comparação
        acao = int(inscricao)

        if acao == 0:  # INSCREVER
            # Verificar se já está inscrito ativamente
            if inscricao_existente and inscricao_existente[0] == 0: # Se a situação for 0 (não cancelada)
                flash('Você já está inscrito nesta aula!', 'error')
                return redirect(url_for('abrir_dashbordaluno', id=id_usuario))

            # Verificar capacidade da aula
            cursor.execute("""
                SELECT COUNT(*) 
                FROM AULAS_ALUNO 
                WHERE ID_AULAS = ? AND SITUACAO = 0
            """, (id,))
            inscritos = cursor.fetchone()[0]

            cursor.execute("SELECT CAPACIDADE FROM AULAS WHERE ID_AULAS = ?", (id,))
            capacidade_total = cursor.fetchone()[0]

            if inscritos >= capacidade_total:
                flash('A aula atingiu a capacidade máxima!', 'error')
                return redirect(url_for('abrir_dashbordaluno', id=id_usuario))

            # Verificar conflito de horário
            cursor.execute("""
                SELECT a.HORA, a.HORA_FIM, a.SEGUNDA, a.TERCA, a.QUARTA, a.QUINTA, a.SEXTA, a.SABADO
                FROM AULAS a
                WHERE a.ID_AULAS = ?
            """, (id,))
            nova_aula = cursor.fetchone()


            if not nova_aula:
                flash('Aula não encontrada.', 'error')
                return redirect(url_for('abrir_dashbordaluno', id=id_usuario))

            hora_inicio, hora_fim, segunda, terca, quarta, quinta, sexta, sabado = nova_aula

            cursor.execute("""
                SELECT 1
                FROM AULAS_ALUNO aa
                INNER JOIN AULAS a ON a.ID_AULAS = aa.ID_AULAS
                WHERE aa.ID_USUARIO = ? 
                  AND aa.SITUACAO = 0
                  AND (
                    (a.SEGUNDA = 1 AND ? = 1) OR
                    (a.TERCA   = 1 AND ? = 1) OR
                    (a.QUARTA  = 1 AND ? = 1) OR
                    (a.QUINTA  = 1 AND ? = 1) OR
                    (a.SEXTA   = 1 AND ? = 1) OR
                    (a.SABADO  = 1 AND ? = 1)
                  )
                  AND (
                    (? BETWEEN a.HORA AND a.HORA_FIM) OR
                    (a.HORA BETWEEN ? AND ?) OR
                    (? BETWEEN a.HORA AND a.HORA_FIM)
                  )
            """, (
                id_usuario,
                segunda, terca, quarta, quinta, sexta, sabado,
                hora_inicio, hora_inicio, hora_fim, hora_fim
            ))

            conflito = cursor.fetchone()

            if conflito:
                flash('Você já tem uma aula neste horário!', 'error')
                return redirect(url_for('abrir_dashbordaluno', id=id_usuario))

            # Fazer inscrição (INSERT ou UPDATE se já existir registro inativo)
            if inscricao_existente:
                # Já existe registro, apenas reativar
                cursor.execute("""
                    UPDATE AULAS_ALUNO 
                    SET SITUACAO = 0 
                    WHERE ID_AULAS = ? AND ID_USUARIO = ?
                """, (id, id_usuario))
            else:
                # Nova inscrição
                cursor.execute("""
                    INSERT INTO AULAS_ALUNO (ID_AULAS, ID_USUARIO, SITUACAO)
                    VALUES (?, ?, 0)
                """, (id, id_usuario))

            con.commit()
            flash('Inscrição realizada com sucesso!', 'success')

        elif acao == 1:  # CANCELAR INSCRIÇÃO
            if not inscricao_existente:
                flash('Você não está inscrito nesta aula!', 'error')
                return redirect(url_for('abrir_dashbordaluno', id=id_usuario))

            # Fazer cancelamento (UPDATE)
            cursor.execute("""
                UPDATE AULAS_ALUNO 
                SET SITUACAO = 1 
                WHERE ID_USUARIO = ? AND ID_AULAS = ?
            """, (id_usuario, id))

            con.commit()
            flash('Inscrição cancelada com sucesso!', 'success')

    except Exception as e:
        con.rollback()
        flash(f'Erro ao processar solicitação', 'error')


    finally:
        cursor.close()

    return redirect(url_for('abrir_dashbordaluno', id=id_usuario))

# -------------------------------------------------------
# aulas que ja estão esgotadas. /relatorio_aulas_esgotadas
# -------------------------------------------------------

@app.route('/relatorio_aulas_esgotadas', methods=['GET'])
def relatorio_aulas_esgotadas():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT 
                a.id_aulas,
                u.nome AS professor,
                m.nome AS modalidade,
                a.capacidade,
                (SELECT COUNT(*) FROM AULAS_ALUNO aa WHERE aa.ID_AULAS = a.id_aulas) AS alunos_inscritos,
                a.hora, a.hora_fim,
                CASE a.segunda WHEN 1 THEN 'Seg ' ELSE '' END ||
                CASE a.terca   WHEN 1 THEN 'Ter ' ELSE '' END ||
                CASE a.quarta  WHEN 1 THEN 'Qua ' ELSE '' END ||
                CASE a.quinta  WHEN 1 THEN 'Qui ' ELSE '' END ||
                CASE a.sexta   WHEN 1 THEN 'Sex ' ELSE '' END ||
                CASE a.sabado  WHEN 1 THEN 'Sab ' ELSE '' END AS dias_semana
            FROM aulas a
            INNER JOIN usuario u ON a.id_usuario = u.id_usuario
            INNER JOIN modalidade m ON a.id_modalidade = m.id_modalidade
            WHERE a.capacidade <= (SELECT COUNT(*) FROM AULAS_ALUNO aa WHERE aa.ID_AULAS = a.id_aulas)
            ORDER BY m.nome, a.hora
        """)
        aulas = cursor.fetchall()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, "Relatório de Aulas Esgotadas", ln=True, align="C")
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=True)
        pdf.ln(5)

        # Cabeçalho da tabela (sempre exibido)
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(15, 8, "ID", 1)
        pdf.cell(50, 8, "Modalidade", 1)
        pdf.cell(40, 8, "Professor", 1)
        pdf.cell(25, 8, "Dias", 1)
        pdf.cell(30, 8, "Horário", 1)
        pdf.cell(25, 8, "Vagas", 1, ln=True)

        pdf.set_font("Arial", size=9)

        if not aulas:
            # Exibe linha informando que não há registros
            pdf.cell(185, 8, "Nenhuma aula está esgotada no momento.", 1, ln=True, align="C")
        else:
            for a in aulas:
                id_aula, professor, modalidade, capacidade, inscritos, hora, hora_fim, dias = a
                vagas_restantes = capacidade - inscritos  # sempre 0 ou negativo
                pdf.cell(15, 8, str(id_aula), 1)
                pdf.cell(50, 8, modalidade[:20], 1)
                pdf.cell(40, 8, professor[:20], 1)
                pdf.cell(25, 8, dias.strip(), 1)
                pdf.cell(30, 8, f"{hora}-{hora_fim}", 1)
                pdf.cell(25, 8, str(0 if vagas_restantes < 0 else vagas_restantes), 1, ln=True)

        nome_arquivo = "relatorio_aulas_esgotadas.pdf"
        pdf.output(nome_arquivo)
        return send_file(nome_arquivo, as_attachment=True, mimetype='application/pdf')

    except Exception as e:
        flash(f"Erro ao gerar relatório", "error")
        return redirect(url_for('abrir_tabelaaulasadm'))
    finally:
        cursor.close()




# -------------------------------------------------------
# aulas que ainda restam vagas relatorio_aulas_disponiveis
# -------------------------------------------------------

@app.route('/relatorio_aulas_disponiveis', methods=['GET'])
def relatorio_aulas_disponiveis():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT 
                a.id_aulas,
                u.nome AS professor,
                m.nome AS modalidade,
                a.capacidade,
                (SELECT COUNT(*) FROM AULAS_ALUNO aa WHERE aa.ID_AULAS = a.id_aulas) AS alunos_inscritos,
                a.hora, a.hora_fim,
                CASE a.segunda WHEN 1 THEN 'Seg ' ELSE '' END ||
                CASE a.terca   WHEN 1 THEN 'Ter ' ELSE '' END ||
                CASE a.quarta  WHEN 1 THEN 'Qua ' ELSE '' END ||
                CASE a.quinta  WHEN 1 THEN 'Qui ' ELSE '' END ||
                CASE a.sexta   WHEN 1 THEN 'Sex ' ELSE '' END ||
                CASE a.sabado  WHEN 1 THEN 'Sab ' ELSE '' END AS dias_semana
            FROM aulas a
            INNER JOIN usuario u ON a.id_usuario = u.id_usuario
            INNER JOIN modalidade m ON a.id_modalidade = m.id_modalidade
            WHERE a.capacidade > (SELECT COUNT(*) FROM AULAS_ALUNO aa WHERE aa.ID_AULAS = a.id_aulas)
            ORDER BY m.nome, a.hora
        """)
        aulas = cursor.fetchall()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, "Relatório de Aulas com Vagas Disponíveis", ln=True, align="C")
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=True)
        pdf.ln(5)

        if not aulas:
            pdf.cell(200, 10, "Todas as aulas estão esgotadas no momento.", ln=True)
        else:
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(15, 8, "ID", 1)
            pdf.cell(50, 8, "Modalidade", 1)
            pdf.cell(40, 8, "Professor", 1)
            pdf.cell(25, 8, "Dias", 1)
            pdf.cell(30, 8, "Horário", 1)
            pdf.cell(25, 8, "Vagas", 1, ln=True)

            pdf.set_font("Arial", size=9)
            for a in aulas:
                id_aula, professor, modalidade, capacidade, inscritos, hora, hora_fim, dias = a
                vagas_restantes = capacidade - inscritos
                pdf.cell(15, 8, str(id_aula), 1)
                pdf.cell(50, 8, modalidade[:20], 1)
                pdf.cell(40, 8, professor[:20], 1)
                pdf.cell(25, 8, dias.strip(), 1)
                pdf.cell(30, 8, f"{hora}-{hora_fim}", 1)
                pdf.cell(25, 8, str(vagas_restantes), 1, ln=True)

        nome_arquivo = "relatorio_aulas_disponiveis.pdf"
        pdf.output(nome_arquivo)
        return send_file(nome_arquivo, as_attachment=True, mimetype='application/pdf')

    except Exception as e:
        flash(f"Erro ao gerar relatório", "error")
        return redirect(url_for('abrir_tabelaaulasadm'))
    finally:
        cursor.close()

# -------------------------------------------------------
# EXECUÇÃO DA APLICAÇÃO
# -------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)