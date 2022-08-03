from app import db


class User(db.Model):
    """model for storing user information and user id"""

    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

    def save_to_db(self) -> "User":
        db.session.add(self)
        db.session.commit()
        return self