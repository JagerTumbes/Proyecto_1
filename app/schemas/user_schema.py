from app import ma
from app.models.user import User
import marshmallow as mm

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        # Excluir password_hash de la salida
        exclude = ("password_hash",)

    # Campo de entrada: contraseña (no se guarda directamente)
    password = mm.fields.String(required=True, load_only=True)
    # Campo de entrada: confirmación de contraseña
    password_confirm = mm.fields.String(required=True, load_only=True)

    # Campo de salida: ID del usuario
    id = mm.fields.Int(dump_only=True)
    # Campo de salida: rol del usuario
    role = mm.fields.String(dump_only=True)

    # Validación personalizada para asegurar que password y password_confirm coincidan
    @mm.validates_schema
    def validate_passwords(self, data, **kwargs):
        if data.get("password") != data.get("password_confirm"):
            raise mm.ValidationError("Passwords must match", "password_confirm")