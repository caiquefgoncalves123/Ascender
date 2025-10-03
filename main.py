from flask import Flask, render_template, redirect, request, flash, url_for, session, send_from_directory, send_file
import fdb
from flask_bcrypt import generate_password_hash, check_password_hash
from fpdf import FPDF

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'

host = 'localhost'
database = r'C:\Users\Aluno\Desktop\ASCENDER.FDB'
user ='sysdba'
password ='sysdba'

con = fdb.connect(user= user, password=password, host=host, database= database)

@app.route('/')
def index():
    return render_template('home.html')


@app.route('/abrir_login')
def abrir_login():
    return render_template('login.html')

# @app.route('/abrir_cadastro')
# def abrir_cadastro():
#     return (render_template('cadastro.html'))

@app.route('/abrir_dashbordaluno')
def abrir_dashbordaluno():
    return (render_template('dashboardaluno.html'))

@app.route('/cadastro', methods= ['GET','POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        cpf = request.form['cpf']
        #tipo = request.form['tipo']
        telefone = request.form['telefone']
        senha = request.form['senha']
        confirma = request.form['confirma']
        if senha != confirma:
            flash("Senhas não coincidem!")
            return redirect(url_for('cadastro'))
        if len(senha) < 8 or len(senha) > 12:
            flash('A senha deve ter entre 8 e 12 caracteres.', 'danger')
            return redirect(url_for('cadastro'))

            # validação de complexidade da senha
        maiuscula = False
        minuscula = False
        numero = False
        caracterpcd = False
        for s in senha:
            if s.isupper():
                maiuscula = True
            if s.islower():
                minuscula = True
            if s.isdigit():
                numero = True
            if not s.isalnum():
                caracterpcd = True

        if not (maiuscula or minuscula or numero or caracterpcd):
            flash(
                'A senha deve conter ao menos uma letra maiúscula, '
                'uma letra minúscula, um número e um caractere especial.',
                'danger')
            return redirect(url_for('cadastro'))
        senha_cripto = generate_password_hash(senha).decode('utf-8')


        cursor = con.cursor()
        try:
            cursor.execute("SELECT 1 FROM usuario WHERE email = ?", (email,))
            if cursor.fetchone():
                flash('Esse e-mail já está cadastrado!', 'error')
                return redirect(url_for('cadastro'))

            cursor.execute(
                "INSERT INTO usuario (tipo, nome, email, cpf, telefone, senha) VALUES (?, ?, ?, ?, ?, ?)",
                (2, nome, email, cpf, telefone, senha_cripto)
            )
            con.commit()

        finally:
            cursor.close()



        flash('Usuário cadastrado com sucesso!', 'success')
        return render_template('login.html', aluno=nome)
    return (render_template('cadastro.html'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        cursor = con.cursor()
        try:
            cursor.execute("SELECT senha, id_usuario, nome FROM usuario WHERE email = ?", (email,))
            usuario = cursor.fetchone()

            if usuario and check_password_hash(usuario[0], senha):
                session['id_usuario'] = usuario[1]
                flash('Login realizado com sucesso!', 'success')
                return render_template('dashboardaluno.html', aluno=usuario[2])

            else:
                flash('E-mail ou senha incorretos. Tente novamente.', 'error')
                return redirect(url_for('login'))
        finally:
            cursor.close()

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop("id_usuario",None)
    return redirect(url_for('index'))





if __name__ == '__main__':
    app.run(debug=True)