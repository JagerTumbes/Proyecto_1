from app.models.user import User

class Director(User):
    __mapper_args__ = {
        'polymorphic_identity': 'director',
    }