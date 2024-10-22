from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt



class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)  # Ensure username is unique
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # relationships
    recipes = db.relationship('Recipe', back_populates='user')

    @validates('username')
    def validate_username(self, key, value):
        if value is None or value.strip() == '':
            raise ValueError('Username is required.')
        if User.query.filter(User.username == value).first():
            raise ValueError('Username is already taken.')
        return value  # Return the validated value

    @hybrid_property
    def password(self):
        raise AttributeError("Password is not accessible.")

    @password.setter
    def password(self, value):
        self._password_hash = bcrypt.generate_password_hash(value).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Ensure user_id is not null
    
    # Establish relationship back to User
    user = db.relationship('User', back_populates='recipes')
    
    @validates('title')
    def validate_title(self, key, value):
        if value is None or value.strip() == '':
            raise ValueError('Title is required.')
        return value  # Return the validated value

    @validates('instructions')
    def validate_instructions(self, key, value):
        if value is None or value.strip() == '':
            raise ValueError('Instructions are required.')
        if len(value) < 50:
            raise ValueError('Instructions must be at least 50 characters long.')
        return value  # Return the validated value

    @validates('minutes_to_complete')
    def validate_minutes(self, key, value):
        if value < 0:
            raise ValueError('Minutes to complete must be a non-negative integer.')
        return value  # Return the validated value
    