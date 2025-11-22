from app.models.user import User

class Alumno(User):
    __mapper_args__ = {
        'polymorphic_identity': 'alumno',
    }