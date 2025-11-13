from app import db
from app.models.user import User

def register_user(data):
    user = User(
        username=data['username'],
        email=data['email'],
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return user

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()