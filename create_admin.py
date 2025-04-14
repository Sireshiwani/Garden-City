from app import app, db
from models import User
from werkzeug.security import generate_password_hash


# Admin call
def admin_user():
    with app.app_context():
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(
                username='admin',
                email='james@gcfc.com',
                password=generate_password_hash('admin!234', method='pbkdf2:sha256:600000'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created!")
        else:
            print("Admin user already exists!")