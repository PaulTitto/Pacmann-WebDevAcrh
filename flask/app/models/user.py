from app.extensions import db

class Users(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique = True)
    email = db.Column(db.String(128))
    password = db.Column(db.String(128))
    role = db.Column(db.String(80), nullable=False, server_default='user')

    def has_role(self, role_name):
        return self.role == role_name
    
    @property
    def is_authenticated(self):
        return True if self.user_id is not None else False

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user_id

    # Required for administrative interface
    def __unicode__(self):
        return self.username
    

    def serialize(self): 
        return {
            "username": self.username,
            "email": self.email,
            "password": self.password
        }