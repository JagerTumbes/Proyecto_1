from app.models.user import User

class SuperAdmin(User):
    __mapper_args__ = {
        'polymorphic_identity': 'superadmin',
    }

    # Puedes añadir campos específicos aquí si es necesario en el futuro
    # Por ejemplo: special_permission_level = db.Column(db.Integer, default=999)