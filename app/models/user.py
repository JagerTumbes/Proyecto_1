from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Enum
import enum

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # Usaremos esta columna como discriminator para la herencia
    role = db.Column(db.String(15), nullable=False) # 'superadmin', 'director', etc.

    # Relación con las tareas (puede ser común a todos)
    tasks = db.relationship('Task', backref='owner', lazy=True, cascade='all, delete-orphan')

    # Polimorfismo: Definir la herencia con una columna discriminator
    __mapper_args__ = {
        'polymorphic_identity': 'user',  # Valor por defecto
        'polymorphic_on': role           # Columna que define el tipo
    }

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'