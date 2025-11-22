from app.models.user import User

class Administrativo(User):
    __mapper_args__ = {
        'polymorphic_identity': 'administrativo',
    }