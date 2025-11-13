from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from app.models.user import User
from app.schemas.user_schema import UserSchema
from app.services.auth_service import register_user, get_user_by_email
import marshmallow as mm
from app.utils.decorators import role_required

auth_bp = Blueprint('auth', __name__)

user_schema = UserSchema()

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Registro de un nuevo usuario
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

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Iniciar sesión
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
        description: Login exitoso, devuelve token
        schema:
          type: object
          properties:
            access_token:
              type: string
      400:
        description: Email y contraseña son requeridos
      401:
        description: Credenciales inválidas
    """
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"msg": "Email and password required"}), 400

        user = get_user_by_email(email)
        if user and user.check_password(password):
            token = create_access_token(identity={"id": user.id, "role": user.role})
            return jsonify({"access_token": token}), 200

        return jsonify({"msg": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500
    
@auth_bp.route('/users', methods=['GET'])
@role_required('admin')
def list_users():
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