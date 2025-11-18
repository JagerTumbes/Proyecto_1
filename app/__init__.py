from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flasgger import Swagger
from flask_migrate import Migrate
from app.config import Config

db = SQLAlchemy()
jwt = JWTManager()
ma = Marshmallow()
swagger = Swagger()
migrate = Migrate()

# Importar modelos para que Alembic los reconozca
from app.models import user, task

def create_app():
    app = Flask(__name__, template_folder='../templates')
    app.config.from_object(Config)

    # Asegúrate de que la app tenga una clave secreta para las sesiones
    app.secret_key = app.config['SECRET_KEY']

    # Inicializar extensiones
    db.init_app(app)
    jwt.init_app(app)
    ma.init_app(app)
    swagger.init_app(app)
    migrate.init_app(app, db)

    # Registrar blueprints
    from app.routes.auth import auth_bp
    from app.routes.tasks import tasks_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(tasks_bp, url_prefix='/tasks')

    return app