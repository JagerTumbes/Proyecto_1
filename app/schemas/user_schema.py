from app import ma
from app.models.user import User
import marshmallow as mm  # Importar marshmallow como mm

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        exclude = ("password_hash",)

    # Campo adicional para confirmar contraseña en el registro
    password_confirm = mm.fields.String(required=True, load_only=True)

    # Validación personalizada para asegurar que password y password_confirm coincidan
    @mm.validates_schema  # Usar mm.validates_schema, no ma.validates_schema
    def validate_passwords(self, data, **kwargs):
        if data.get("password") != data.get("password_confirm"):
            raise mm.ValidationError("Passwords must match", "password_confirm")