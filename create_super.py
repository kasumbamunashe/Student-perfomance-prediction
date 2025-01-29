from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'postgresql://postgres:Munashe056@localhost/student'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(120), nullable=False)  # 'admin', 'teacher', etc.
    reset_token = db.Column(db.String(255), nullable=True)

# Create a super admin user
def create_super_admin():
    with app.app_context():
        # Create tables if they do not exist
        db.create_all()

        # Check if the super admin already exists
        super_admin = User.query.filter_by(username='superadmin').first()
        if not super_admin:
            hashed_password = bcrypt.generate_password_hash('superadmin_password').decode('utf-8')
            super_admin = User(username='superadmin', email='superadmin@gmail.com', password=hashed_password, role='admin')
            db.session.add(super_admin)
            db.session.commit()
            print("Super admin created successfully!")
        else:
            print("Super admin already exists.")

if __name__ == "__main__":
    create_super_admin()
