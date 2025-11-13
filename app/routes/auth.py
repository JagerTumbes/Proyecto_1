from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from app.models.user import User
from app.schemas.user_schema import UserSchema
from app.services.auth_service import register_user, get_user_by_email
from werkzeug.security import check_password_hash

auth_bp = Blueprint('auth', __name__)

user_schema = UserSchema()

@auth_bp.route('/register', methods=['POST'])
def register():
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