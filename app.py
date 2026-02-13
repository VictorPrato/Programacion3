from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer
from functools import wraps
import os 

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = os.getenv('secret_key','supersecretkey')
client = MongoClient(os.getenv('MONGO_URI'))
db = client['bdproyecto'] 
collection = db['usuarios'] 

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')  
serializer = Serializer(app.secret_key, salt='password-reset-salt')

def enviar_email(destinatario, asunto, cuerpo):
    mensaje = Mail(
        from_email='victorprato06@gmail.com',  
        to_emails=destinatario,
        subject=asunto,
        html_content=cuerpo
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)  
        response = sg.send(mensaje)
        print(f"Correo enviado con éxito! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

# roles
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'usuario' not in session:
                return redirect(url_for('login'))
            
            user = collection.find_one({'usuario': session['usuario']})
            if not user or user.get('rol') != role:
                flash("No tienes permisos para acceder a esta página.")
                return redirect(url_for('home'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def home():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    # Obtener el usuario de la base de datos
    user = collection.find_one({'usuario': session['usuario']})
    
    if not user:
        session.pop('usuario', None)
        return redirect(url_for('login'))
    
    # Redirigir según el rol
    if user.get('rol') == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('index'))

@app.route('/pagina_principal')
def pagina_principal():
    """Ruta que redirige a la página principal según el rol del usuario"""
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    # Obtener el usuario de la base de datos
    user = collection.find_one({'usuario': session['usuario']})
    
    if not user:
        session.pop('usuario', None)
        return redirect(url_for('login'))
    
    # Redirigir según el rol
    if user.get('rol') == 'admin':
        return redirect(url_for('admin_dashboard'))  # Admin va al panel de administración
    else:
        return redirect(url_for('index'))  # Usuario regular va a la tienda

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        email = request.form['email']
        contrasena = request.form['contrasena']
        
        # Verificar si el correo ya existe
        if collection.find_one({'email': email}):
            flash("El correo electrónico ya está registrado.")
            return redirect(url_for('registro'))

        # Hash de la contraseña
        hashed_password = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        # Insertar usuario en la base de datos con rol por defecto 'usuario'
        collection.insert_one({
            'usuario': usuario,
            'email': email,
            'contrasena': hashed_password,
            'rol': 'usuario'  # Por defecto todos son usuarios
        })
        
        session['usuario'] = usuario
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']

        # Buscar al usuario en la base de datos
        user = collection.find_one({'usuario': usuario})
        
        # Verificar si las credenciales son correctas
        if user and bcrypt.check_password_hash(user['contrasena'], contrasena):
            session['usuario'] = usuario
            
            # Redirigir según el rol
            if user.get('rol') == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            flash("Usuario o contraseña incorrectos.")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/index')
@role_required('usuario')
def index():
    return render_template('index.html', usuario=session['usuario'])

@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    return render_template('paneladmin.html', usuario=session['usuario'])

@app.route('/mi_perfil')
def mi_perfil():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    usuario = session['usuario']
    user_data = collection.find_one({'usuario': usuario})
    return render_template('mi_perfil.html', usuario=user_data['usuario'], email=user_data['email'])

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        email = request.form['email']
        usuario = collection.find_one({'email': email})

        if usuario:
            token = serializer.dumps(email, salt='password-reset-salt')
            enlace = url_for('restablecer_contrasena', token=token, _external=True)
            asunto = "Recuperación de contraseña"
            cuerpo = f"""
            <p>Hola, hemos recibido una solicitud para restablecer tu contraseña.</p>
            <p>Si no has solicitado este cambio, ignora este mensaje.</p>
            <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
            <a href="{enlace}">Restablecer contraseña</a>
            """
            enviar_email(email, asunto, cuerpo)
            flash("Te hemos enviado un correo para recuperar tu contraseña.", "success")
        else:
            flash("El correo electrónico no está registrado.", "error")

    return render_template('recuperar_contrasena.html')

@app.route('/restablecer_contrasena/<token>', methods=['GET', 'POST'])
def restablecer_contrasena(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("El enlace de restablecimiento ha caducado o es inválido.", "error")
        return redirect(url_for('recuperar_contrasena'))

    if request.method == 'POST':
        nueva_contrasena = request.form['nueva_contrasena']
        hashed_password = bcrypt.generate_password_hash(nueva_contrasena).decode('utf-8')
        collection.update_one({'email': email}, {'$set': {'contrasena': hashed_password}})
        flash("Tu contraseña ha sido restablecida con éxito.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Esto permite que Render asigne el puerto y que la app sea visible (0.0.0.0)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
#se cambio la direccion de los puertos para evitar errores en render