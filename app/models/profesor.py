from app.models.user import User

class Profesor(User):
    __mapper_args__ = {
        'polymorphic_identity': 'profesor',
    }