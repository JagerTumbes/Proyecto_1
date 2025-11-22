from app import db
from app.models.user import User
from app.models.superadmin import SuperAdmin
from app.models.director import Director
from app.models.administrativo import Administrativo
from app.models.profesor import Profesor
from app.models.alumno import Alumno


def register_user(data, role='alumno'):
    # Mapear string de rol a la clase correspondiente
    from app.models.superadmin import SuperAdmin
    from app.models.director import Director
    from app.models.administrativo import Administrativo
    from app.models.profesor import Profesor
    from app.models.alumno import Alumno

    role_class_map = {
        'superadmin': SuperAdmin,
        'director': Director,
        'administrativo': Administrativo,
        'profesor': Profesor,
        'alumno': Alumno,
    }

    user_class = role_class_map.get(role, Alumno) # Por defecto alumno

    user = user_class(
        username=data['username'],
        email=data['email'],
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return user

def get_user_by_email(email):
    """
    Busca un usuario por su email.
    Debido a la herencia, puede devolver una instancia de cualquier subclase de User.
    """
    return User.query.filter_by(email=email).first()