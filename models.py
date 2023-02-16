from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import datetime

db = SQLAlchemy()

#from .models import User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    role = db.Column(db.Integer)

    def __init__(self, email, password, name, role):
        self.email=email
        self.password=password
        self.name=name
        self.role=role


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

    def __init__(self, name):
        self.name=name


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer)
    name = db.Column(db.String(80))
    description = db.Column(db.String(100))
    price = db.Column(db.Numeric(precision=10, scale=2))
    image = db.Column(db.String(80))
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.datetime.now())

    def __init__(self, category_id, name, description, price, image, created_at):
        self.category_id=category_id
        self.name=name
        self.description=description
        self.price=price
        self.image=image
        self.created_at=created_at


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    product_id = db.Column(db.Integer)
    qty = db.Column(db.Integer)

    def __init__(self, user_id, product_id, qty):
        self.user_id=user_id
        self.product_id=product_id
        self.qty=qty


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    reference = db.Column(db.String(80), unique=True)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.datetime.now())

    def __init__(self, user_id, reference, created_at):
        self.user_id=user_id
        self.reference=reference
        self.created_at=created_at


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer)
    product_id = db.Column(db.Integer)
    qty = db.Column(db.Integer)
    unit_price = db.Column(db.Numeric(precision=10, scale=2))
    total_price = db.Column(db.Numeric(precision=10, scale=2))

    def __init__(self, order_id, product_id, qty, unit_price, total_price):
        self.order_id=order_id
        self.product_id=product_id
        self.qty=qty
        self.unit_price=unit_price
        self.total_price=total_price


class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    product_id = db.Column(db.Integer)
    message = db.Column(db.String(300))
    subjective = db.Column(db.Numeric(precision=10, scale=4))
    polarity = db.Column(db.Numeric(precision=10, scale=4))
    analysis = db.Column(db.String(20))
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.datetime.now())

    def __init__(self, user_id, product_id, message, subjective, polarity, analysis, created_at):
        self.user_id=user_id
        self.product_id=product_id
        self.message=message
        self.subjective=subjective
        self.polarity=polarity
        self.analysis=analysis
        self.created_at=created_at
