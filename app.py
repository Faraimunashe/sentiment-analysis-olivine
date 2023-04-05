from flask import Flask, jsonify, request, redirect, render_template, url_for, flash, session,wrappers
from flask_session import Session
from flask_login import LoginManager, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os
from models import *
from functools import wraps
from textblob import TextBlob


# You can change this to any folder on your system
ALLOWED_EXTENSIONS = {'jpeg'}
ROWS_PER_PAGE = 8
CART_COUNT = 0


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


#check cart
def cart_not_empty(f):
    @wraps(f)
    def decorated_cart_func(*args, **kwargs):
        if session['cart'] != None:
            return f(*args, **kwargs)
        else:
            return redirect("/")
    return decorated_cart_func


#handling cart
def handle_cart():
    products = []
    grand_total = 0
    index = 0
    quantity_total = 0

    for item in session['cart']:
        product = Product.query.filter_by(id=item['id']).first()

        quantity = int(item['quantity'])
        total = quantity * product.price
        grand_total += total

        quantity_total += quantity

        products.append({'id': product.id, 'name': product.name, 'price':  product.price,
                         'image': product.image, 'quantity': quantity, 'total': total, 'index': index})
        index += 1

    grand_total_plus_shipping = grand_total + 0

    return products, grand_total, grand_total_plus_shipping, quantity_total


def analyse(x):
    if x >= 0.5:
        return 'Positive'
    elif x <= -0.5:
        return 'Negative'
    else:
        return 'Neutral'


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


@app.route('/add-to-cart/<id>', methods=['GET'])
@login_required
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append({'id': id, 'quantity': 1})
    session.modified = True

    print(session['cart'])
    return redirect(url_for('index'))


@app.route('/add-to-cart', methods=['POST'])
@login_required
def post_to_cart():
    id = int(request.form.get('product_id'))
    qty = int(request.form.get('qty'))
    if id == '' or qty == '':
        flash('some fields are empty.')
        return redirect(url_for('details'))

    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append({'id': id, 'quantity': qty})
    session.modified = True

    return redirect(url_for('details'))


@app.route('/remove-from-cart/<index>')
@login_required
def remove_from_cart(index):
    del session['cart'][int(index)]
    session.modified = True
    return redirect(url_for('cart'))


#cart
@app.route('/cart')
@cart_not_empty
def cart():
    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart()
    print(len(session['cart']))

    return render_template('cart.html', products=products, grand_total=grand_total, grand_total_plus_shipping=grand_total_plus_shipping, quantity_total=quantity_total)


#product details
@app.route('/product-details/<id>', methods=['GET'])
@login_required
def details(id):
    product = Product.query.filter_by(id=id).first()
    reviews = db.session.query(
    Reviews.id,
    Reviews.message,
    Reviews.product_id,
    User.id,
    User.name).join(
    Reviews, Reviews.user_id == User.id).filter(Reviews.product_id==product.id).all() 
    category = Category.query.filter_by(id=product.category_id).first()
    

    image = 'products/'+ str(product.image[16:])
    print(reviews)
    
    return render_template('details.html', product=product, reviews=reviews, category=category, image=image)


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

    neg_count = Reviews.query.filter_by(analysis='Negative').count()
    pos_count = Reviews.query.filter_by(analysis='Positive').count()
    neu_count = Reviews.query.filter_by(analysis='Neutral').count()
    #print(neg_count, pos_count, neu_count)
    return render_template('dashboard.html', neg_count=neg_count, pos_count=pos_count, neu_count=neu_count)


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
    
    products = Product.query.all()
    categories = Category.query.all()
    return render_template('product.html', products=products, categories=categories)

@app.route('/delete-product/<id>', methods=['GET'])
@login_required
@admin_role
def deleteproduct(id):
    product = Product.query.filter_by(id=id).first()

    if product == None:
        flash('Specified product is not found!')
        return redirect(url_for('product'))

    db.session.delete(product)
    db.session.commit()

    flash('Successfully deleted product!')
    return redirect(url_for('product'))


@app.route('/delete-category/<id>', methods=['GET'])
@login_required
@admin_role
def deletecategory(id):
    product = Category.query.filter_by(id=id).first()

    if product == None:
        flash('Specified category is not found!')
        return redirect(url_for('category'))

    db.session.delete(product)
    db.session.commit()

    flash('Successfully deleted category!')
    return redirect(url_for('category'))


#Product analysis
@app.route('/product-analysis/<id>', methods=['GET'])
@login_required
@admin_role
def product_analysis(id):
    
    product = Product.query.filter_by(id=id).first()
    image = 'products/'+ str(product.image[16:])

    neg_count = Reviews.query.filter_by(product_id=product.id).filter_by(analysis='Negative').count()
    pos_count = Reviews.query.filter_by(product_id=product.id).filter_by(analysis='Positive').count()
    neu_count = Reviews.query.filter_by(product_id=product.id).filter_by(analysis='Neutral').count()

    reviews = db.session.query(Reviews.id, Reviews.message, Reviews.analysis, Reviews.created_at, User.id, User.name).join(
    Reviews, Reviews.user_id == User.id).filter(Reviews.product_id==product.id).all() 
    return render_template('product-analysis.html', product=product, image=image, neg_count=neg_count, pos_count=pos_count, neu_count=neu_count, reviews=reviews)




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


@app.route('/rate', methods=['POST'])
@login_required
def rate():
    if request.method == 'POST':
        rate = request.form.get('rate')
        productid = request.form.get('product_id')
        ct = datetime.datetime.now()
        blob = TextBlob(request.form.get('rate'))

        if rate == '':
            flash('Rating field is required!')
            return redirect(url_for('index'))

        new_review = Reviews(user_id=session['userid'], product_id=productid, message=rate, subjective=round(blob.sentiment.subjectivity,2), polarity=round(blob.sentiment.polarity,2), analysis=analyse(blob.sentiment.polarity), created_at=ct)
        db.session.add(new_review)
        db.session.commit()

        flash('Successfully added new rating!')
    
    return redirect(url_for('index'))


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    g=None
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)