from flask import Flask, jsonify, request, redirect, render_template, url_for, flash, session,wrappers
from flask_session import Session
from flask_login import LoginManager, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os
from models import *
from functools import wraps


# You can change this to any folder on your system
ALLOWED_EXTENSIONS = {'jpeg'}
ROWS_PER_PAGE = 8


app = Flask(__name__)
app.config['SECRET_KEY'] = 'ProfessorSecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/olivine_db'

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


#check roles
def admin_role(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        user = User.query.filter_by(id=session['userid']).first()
        if user.role == 1:
            return f(*args, **kwargs)
        else:
            return redirect("/")
    return decorated_func


@app.route('/', methods=['GET', 'POST'])
def index():
    categories = Category.query.all()
    #products = Product.query.all()
    if request.method == 'POST':
        search = request.form.get('search')
        products = Product.query.filter_by(name=search).all()

    page = request.args.get('page', 1, type=int)
    products = Product.query.paginate(page=page, per_page=ROWS_PER_PAGE)
    return render_template('index.html', products=products, categories=categories)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email == '' or password == '':
            flash('some fields are empty.')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid login details.')
            return redirect(url_for('login'))
        if check_password_hash(user.password, password):
            login_user(user)
            session['userid'] = user.id
            return redirect(url_for('dashboard'))

        flash('Invalid login details.')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password_confirmation')

        if password != password2:
            flash('Password confirmation should match!')
            return redirect(url_for('register'))

        if len(password) <= 7:
            flash('Password should be 8 characters or greater!')
            return redirect(url_for('register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists!')
            return redirect(url_for('register'))
        new_user = User(email=email, password=generate_password_hash(password, method='sha256'), name=name, role=2)
        db.session.add(new_user)
        db.session.commit()

        flash('Successfully registered new user!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET'])
@login_required
@admin_role
def dashboard():
    return render_template('dashboard.html')


#Categories
@app.route('/categories', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@admin_role
def category():
    if request.method == 'POST':
        name = request.form.get('name')

        if name == '':
            flash('Name field is required!')
            return redirect(url_for('category'))

        new_category = Category(name=name)
        db.session.add(new_category)
        db.session.commit()

        flash('Successfully added new category!')
    
    if request.method == 'PUT':
        category_id = request.form.get('category_id')
        name = request.form.get('name')

        category = Category.query.filter_by(id=category_id).first()
        if name == '':
            flash('Name field is required!')
            return redirect(url_for('category'))

        if category == None:
            flash('Specified category is not found!')
            return redirect(url_for('category'))

        category.name = name
        db.session.commit()

        flash('Successfully updated category!')

    if request.method == 'DELETE':
        category_id = request.form.get('category_id')
        category = Category.query.filter_by(id=category_id).first()

        if category == None:
            flash('Specified category is not found!')
            return redirect(url_for('category'))

        db.session.delete(category)
        db.session.commit()

        flash('Successfully deleted category!')

    categories = Category.query.all()
    return render_template('category.html', categories=categories)


#Products
@app.route('/products', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@admin_role
def product():
    if request.method == 'POST':
        if "file1" not in request.files:
            flash('Image was not found!')
            return redirect(url_for('product'))

        category_id = request.form.get('category_id')
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        file1 = request.files["file1"]
        ct = datetime.datetime.now()

        if name == '' or description == '' or price == '' or description == '' or category_id == '':
            flash('Some fields are empty!')
            return redirect(url_for('product'))

        extension = file1.filename.split('.')[1]
        path = os.path.join("static/products", str(ct.timestamp()) +"."+ extension)
        file1.save(path)

        new_product = Product(name=name, category_id=category_id, description=description, price=price, image=path, created_at=ct)
        db.session.add(new_product)
        db.session.commit()

        flash('Successfully added new product!')
    
    if request.method == 'PUT':
        if "file1" not in request.files:
            flash('Image was not found!')
            return redirect(url_for('product'))

        category_id = request.form.get('category_id')
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        file1 = request.files["file1"]
        ct = datetime.datetime.now()

        if name == '' or description == '' or price == '' or description == '' or category_id == '' or product_id == '':
            flash('Some fields are empty!')
            return redirect(url_for('product'))

        product = Product.query.filter_by(id=product_id).first()

        if product == None:
            flash('Specified product was not found!')
            return redirect(url_for('product'))

        extension = file1.filename.split('.')[1]
        path = os.path.join("static/products", str(ct.timestamp()) +"."+ extension)
        file1.save(path)

        product.name = name
        product.description = description
        product.category_id = category_id
        product.price = price
        product.image = path
        db.session.commit()

        flash('Successfully updated product!')

    if request.method == 'DELETE':
        product_id = request.form.get('product_id')
        product = Product.query.filter_by(id=product_id).first()

        if product == None:
            flash('Specified product is not found!')
            return redirect(url_for('product'))

        db.session.delete(product)
        db.session.commit()

        flash('Successfully deleted product!')

    products = Product.query.all()
    categories = Category.query.all()
    return render_template('product.html', products=products, categories=categories)


#orders
@app.route('/orders', methods=['GET'])
@login_required
@admin_role
def order():
    orders = Order.query.all()
    return render_template('orders.html', orders=orders)


#reviews
@app.route('/reviews', methods=['GET'])
@login_required
@admin_role
def reviews():
    reviews = Reviews.query.all()
    return render_template('reviews.html', reviews=reviews)



#users
@app.route('/users', methods=['GET'])
@login_required
@admin_role
def users():
    users = User.query.all()
    return render_template('users.html', users=users)


#my profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@admin_role
def profile():
    if request.method == 'POST':
        password = request.form.get('password')
        newpass = request.form.get('new_password')
        connewpass = request.form.get('new_password_confirmation')

        if newpass == '' or connewpass == '' or password == '':
            flash('some fields are empty.')
            return redirect(url_for('profile'))
        
        if newpass != connewpass:
            flash('Password confimation must match.')
            return redirect(url_for('profile'))

        user = User.query.filter_by(id=session['userid']).first()
        if not user:
            flash('User not found.')
            return redirect(url_for('profile'))
        
        if check_password_hash(user.password, password):
            user.password = generate_password_hash(newpass, method='sha256')
            db.session.commit()
            flash('Successfully changed password.')
            return redirect(url_for('profile'))
        else:
            flash('Incorrect current password.')
            return redirect(url_for('profile'))
    
    user = User.query.filter_by(id=session['userid']).first()
    return render_template('profile.html', user=user)



@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    g=None
    return redirect(url_for('index'))



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)