from urllib import response
from flask import Blueprint, redirect, render_template, request, jsonify, session, url_for
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, jwt_required, unset_jwt_cookies
from app.models.user import User
from app.schemas.user_schema import UserSchema
from app.services.auth_service import register_user, get_user_by_email
import marshmallow as mm
from app.utils.decorators import role_required
from app import db

auth_bp = Blueprint('auth', __name__)

user_schema = UserSchema()

# ========================
# RUTAS PARA LA API (JSON)
# ========================

@auth_bp.route('/api/register', methods=['POST'])
def api_register():
    """
    Registro de un nuevo usuario (API)
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
            - password_confirm
          properties:
            username:
              type: string
              description: Nombre de usuario
            email:
              type: string
              description: Correo electrónico
            password:
              type: string
              description: Contraseña
            password_confirm:
              type: string
              description: Confirmación de contraseña
    responses:
      201:
        description: Usuario registrado exitosamente
        schema:
          type: object
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
            role:
              type: string
      400:
        description: Error en los datos de entrada
    """
    try:
        data = request.get_json()
        errors = user_schema.validate(data)
        if errors:
            return jsonify(errors), 400

        # Verificar si el email o username ya existen
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"msg": "Email already registered"}), 400
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"msg": "Username already taken"}), 400

        user = register_user(data)

        return user_schema.jsonify(user), 201
    except Exception as e:
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500
    
# Ruta API para procesar el registro de superadmin
@auth_bp.route('/api/register/superadmin', methods=['POST'])
@role_required('superadmin') # Solo superadmin puede crear otro superadmin
def api_register_superadmin():
    """
    Registrar un nuevo superadmin (solo para superadmin)
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
            - password_confirm
          properties:
            username:
              type: string
              description: Nombre de usuario
            email:
              type: string
              description: Correo electrónico
            password:
              type: string
              description: Contraseña
            password_confirm:
              type: string
              description: Confirmación de contraseña
    responses:
      201:
        description: Superadmin registrado exitosamente
        schema:
          type: object
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
            role:
              type: string
      400:
        description: Error en los datos de entrada
      403:
        description: Permisos insuficientes
    """
    try:
        data = request.get_json()
        errors = user_schema.validate(data)
        if errors:
            return jsonify(errors), 400

        # Verificar si el email o username ya existen
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"msg": "Email already registered"}), 400
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"msg": "Username already taken"}), 400

        # Crear usuario con rol 'superadmin'
        user = User(
            username=data['username'],
            email=data['email'],
            role='superadmin' # Fijar rol
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()

        return user_schema.jsonify(user), 201
    except Exception as e:
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    """
    Iniciar sesión (API)
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: Correo electrónico
            password:
              type: string
              description: Contraseña
    responses:
      200:
        description: Login exitoso, devuelve token y URL de redirección
        schema:
          type: object
          properties:
            access_token:
              type: string
            redirect_url:
              type: string
              description: URL a la que redirigir al usuario según su rol
      400:
        description: Email y contraseña son requeridos
      401:
        description: Credenciales inválidas
    """
    try:
        print("DEBUG: Iniciando api_login") # Log para depurar
        data = request.get_json()
        print(f"DEBUG: Datos recibidos: {data}") # Log para depurar

        email = data.get('email')
        password = data.get('password')
        print(f"DEBUG: Email: {email}, Password: {'***' if password else 'None'}") # Log para depurar

        if not email or not password:
            print("DEBUG: Email o password faltantes") # Log para depurar
            return jsonify({"msg": "Email and password required"}), 400

        print("DEBUG: Llamando a get_user_by_email") # Log para depurar
        user = get_user_by_email(email)
        print(f"DEBUG: Usuario encontrado: {user}") # Log para depurar

        if user and user.check_password(password):
            print(f"DEBUG: Credenciales válidas para usuario: {user.username}, rol: {user.role}") # Log para depurar
            token = create_access_token(identity={"id": user.id, "role": user.role})

            # Mapear roles a URLs de dashboard
            role_to_dashboard = {
                'superadmin': '/auth/dashboard/superadmin',
                'director': '/auth/dashboard/director', # Debes crear esta ruta y vista
                'administrativo': '/auth/dashboard/administrativo', # Debes crear esta ruta y vista
                'profesor': '/auth/dashboard/profesor', # Debes crear esta ruta y vista
                'alumno': '/auth/dashboard/alumno' # Debes crear esta ruta y vista
            }

            # Obtener la URL según el rol, o redirigir a login si no se encuentra
            redirect_url = role_to_dashboard.get(user.role, '/auth/login')

            print(f"DEBUG: Token generado, redirigiendo a: {redirect_url}") # Log para depurar
            return jsonify({
                "access_token": token,
                "redirect_url": redirect_url
            }), 200
        else:
            print("DEBUG: Credenciales inválidas") # Log para depurar
            return jsonify({"msg": "Invalid credentials"}), 401

    except Exception as e:
        print(f"DEBUG: Error interno en api_login: {e}") # Log para depurar
        import traceback
        traceback.print_exc() # Imprime el traceback completo
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@auth_bp.route('/api/users', methods=['GET'])
@role_required('admin')
def api_list_users():
    """
    Listar todos los usuarios (solo para administradores)
    ---
    tags:
      - Auth
    responses:
      200:
        description: Lista de usuarios
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  username:
                    type: string
                  email:
                    type: string
                  role:
                    type: string
      403:
        description: Acceso denegado (no es admin)
    """
    users = User.query.all()
    result = user_schema.dump(users, many=True)
    return jsonify(result), 200

@auth_bp.route('/api/logout', methods=['POST'])
@jwt_required()  # <-- Añadir este decorador
def api_logout():
    """
    Cerrar sesión (API)
    ---
    tags:
      - Auth
    responses:
      200:
        description: Logout exitoso
        schema:
          type: object
          properties:
            msg:
              type: string
              description: Mensaje de confirmación
    """
    # En este enfoque, el logout se maneja principalmente del lado del cliente.
    # El servidor puede hacer algo si usas token revocation/blacklisting.
    # Por ahora, simplemente confirmamos el logout.
    jti = get_jwt()['jti']  # jti es el ID único del token
    # Aquí podrías añadir el `jti` a una lista negra si usas token revocation.
    # revoke_token(jti)  # <-- función que tendrías que implementar

    return jsonify({"msg": "Successfully logged out"}), 200

@auth_bp.route('/api/verify-session', methods=['GET'])
@jwt_required() # Requiere token JWT
def api_verify_session():
    """
    Verifica si el usuario actual está autenticado y devuelve su rol
    ---
    tags:
      - Auth
    responses:
      200:
        description: Sesión válida
        schema:
          type: object
          properties:
            role:
              type: string
              description: Rol del usuario
      401:
        description: No autorizado (token inválido o expirado)
    """
    current_user_id = get_jwt_identity()['id']
    user = User.query.get_or_404(current_user_id)

    return jsonify({"role": user.role}), 200

# Ruta API para procesar el registro de director
@auth_bp.route('/api/register/director', methods=['POST'])
#@role_required('superadmin') # Solo superadmin puede crear otro director
def api_register_director():
    """
    Registrar un nuevo director (solo para superadmin)
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
            - password_confirm
          properties:
            username:
              type: string
              description: Nombre de usuario
            email:
              type: string
              description: Correo electrónico
            password:
              type: string
              description: Contraseña
            password_confirm:
              type: string
              description: Confirmación de contraseña
    responses:
      201:
        description: Director registrado exitosamente
        schema:
          type: object
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
            role:
              type: string
      400:
        description: Error en los datos de entrada
      403:
        description: Permisos insuficientes
    """
    try:
        data = request.get_json()
        errors = user_schema.validate(data)
        if errors:
            return jsonify(errors), 400

        # Verificar si el email o username ya existen
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"msg": "Email already registered"}), 400
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"msg": "Username already taken"}), 400

        # Crear usuario con rol 'director'
        user = register_user(data, role='director') # <-- Cambio aquí

        return user_schema.jsonify(user), 201
    except Exception as e:
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500
    
@auth_bp.route('/api/register/administrativo', methods=['POST'])
#@role_required('superadmin', 'director') # Superadmin y director pueden crear administrativo
def api_register_administrativo():
    """
    Registrar un nuevo administrativo (solo para superadmin y director)
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
            - password_confirm
          properties:
            username:
              type: string
              description: Nombre de usuario
            email:
              type: string
              description: Correo electrónico
            password:
              type: string
              description: Contraseña
            password_confirm:
              type: string
              description: Confirmación de contraseña
    responses:
      201:
        description: Administrativo registrado exitosamente
        schema:
          type: object
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
            role:
              type: string
      400:
        description: Error en los datos de entrada
      403:
        description: Permisos insuficientes
    """
    try:
        data = request.get_json()
        errors = user_schema.validate(data)
        if errors:
            return jsonify(errors), 400

        # Verificar si el email o username ya existen
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"msg": "Email already registered"}), 400
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"msg": "Username already taken"}), 400

        # Crear usuario con rol 'administrativo'
        user = register_user(data, role='administrativo')

        return user_schema.jsonify(user), 201
    except Exception as e:
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

# ========================
# RUTAS PARA VISTAS HTML (sin lógica de autenticación)
# ========================

@auth_bp.route('/login', methods=['GET'])
def login_view():
    """
    Vista HTML para iniciar sesión
    """
    return render_template('login.html')

@auth_bp.route('/home', methods=['GET'])
def home():
    """
    Vista de inicio
    """
    # Aquí puedes verificar si hay un token JWT en localStorage del navegador
    # pero Flask no puede acceder directamente a localStorage.
    # Este endpoint puede ser accedido solo si el frontend envía el token.
    # Más adelante veremos cómo protegerlo si es necesario.
    return render_template('home.html')

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    Cerrar sesión (para sesiones Flask y tokens JWT)
    """
    # Limpiar la sesión de Flask (si estás usando)
    session.clear()

    # Para tokens JWT, no podemos invalidarlos del lado del servidor de forma sencilla
    # La práctica común es:
    # 1. Limpiar el token del lado del cliente (JavaScript)
    # 2. Opcionalmente, añadir el token a una lista negra (blacklist) en Redis o DB si necesitas invalidación inmediata.

    # Flask-JWT-Extended no puede limpiar un token JWT que viene en el header de una solicitud GET
    # como la que hace el navegador al acceder a la vista HTML después del redirect.
    # Por lo tanto, el token JWT seguirá siendo válido hasta que expire,
    # pero el cliente (frontend) ya no lo tendrá en localStorage.

    # Redirigir a la página de login
    # Flask-JWT-Extended no puede limpiar un token JWT que viene en el header de una solicitud GET
    # como la que hace el navegador al acceder a la vista HTML después del redirect.
    # Por lo tanto, el token JWT seguirá siendo válido hasta que expire,
    # pero el cliente (frontend) ya no lo tendrá en localStorage.
    return redirect(url_for('auth.login_view'))

# Ruta para mostrar el formulario HTML de registro de superadmin
@auth_bp.route('/register/superadmin', methods=['GET'])
#@role_required('superadmin') # Solo superadmin puede acceder
def show_register_superadmin():
    """
    Muestra el formulario para registrar un nuevo superadmin
    """
    return render_template('register_superadmin.html')

@auth_bp.route('/dashboard/superadmin', methods=['GET'])
#@role_required('superadmin') # Solo superadmin puede acceder
def show_superadmin_dashboard():
    """
    Muestra el dashboard exclusivo para superadmin
    """
    return render_template('superadmin/dashboard.html')

@auth_bp.route('/register/director', methods=['GET'])
#@role_required('superadmin') # Solo superadmin puede acceder al formulario de director
def show_register_director():
    """
    Muestra el formulario para registrar un nuevo director
    """
    return render_template('register_director.html')

@auth_bp.route('/register/administrativo', methods=['GET'])
#@role_required('superadmin', 'director') # Superadmin y director pueden acceder al formulario de administrativo
def show_register_administrativo():
    """
    Muestra el formulario para registrar un nuevo administrativo
    """
    return render_template('register_administrativo.html')