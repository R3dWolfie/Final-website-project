import os
import csv
import tempfile
import secrets
from datetime import datetime
from PIL import Image, ExifTags
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, extract
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from errors.handlers import errors
from collections import defaultdict

from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['UPLOAD_FOLDER'] = './static/pics'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'fooferweb@gmail.com'
app.config['MAIL_PASSWORD'] = 'izmqvomflkfhokgj'
app.config['MAIL_DEFAULT_SENDER'] = 'fooferweb@gmail.com'

mail = Mail(app)

bcrypt = Bcrypt(app)
app.register_blueprint(errors)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_file = db.Column(db.String(200), nullable=False)
    sales = db.relationship('Sales', backref='item', lazy=True)  # One-to-many relationship with Sales

    @staticmethod
    def create_item(name, description, price, image_file, author, stock=1):
        item = Item(name=name, description=description, price=price, author=author, image_file=image_file, stock=stock)
        db.session.add(item)
        db.session.commit()
        return item


class Sales(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # New field
    sale_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    quantity = db.Column(db.Integer, nullable=False)
    total_value = db.Column(db.Float, nullable=False)



def make_sale(item_id, quantity, buyer_id):
    item = Item.query.get(item_id)
    if item and item.stock >= quantity:
        sale = Sales(item_id=item_id, buyer_id=buyer_id, quantity=quantity, total_value=item.price * quantity)
        db.session.add(sale)
        item.stock -= quantity  # decrease stock by the quantity sold
        db.session.commit()
        return sale


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='news_author', foreign_keys=[author_id])  # Changed the backref name

    def __init__(self, title, content, author_id):
        self.title = title
        self.content = content
        self.author_id = author_id


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)

    def __init__(self, author, target, content):
        self.author_id = author
        self.target_id = target
        self.content = content


def check_user(user):
    user = db.session.query(User)
    if user == "None":
        new_user = User(username="DefaultUser", password="testing", email="email@gmail.com")
        db.session.add(new_user)
        db.session.commit()
    return user


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Access denied. You need to be an admin to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    check_user(user_id)
    if user_id is not None:
        return User.query.get(int(user_id))
    return None


def send_password_reset_email(recipient, reset_link):
    subject = 'Password Reset Request'
    body = f"Hello,\n\nYou have requested to reset your password. Please click the link below to reset your " \
           f"password:\n\n{reset_link}\n\nIf you did not request a password reset, please ignore this email.\n\nBest " \
           f"regards,\nThe Password Reset Team"

    # Create the email message
    message = Message(subject=subject, recipients=[recipient], body=body)

    # Send the email
    mail.send(message)


def send_user_created_email(user_email):
    subject = 'Account Created'
    body = f'Hello, your account has been successfully created with the email: {user_email}.'
    recipients = [user_email]

    message = Message(subject=subject, body=body, recipients=recipients)

    try:
        mail.send(message)
        return True
    except Exception as e:
        print(f"An error occurred while sending the email: {e}")
        return False


def send_purchase_email(user_email, item_name):
    subject = 'Purchase Confirmation'
    body = f'Thank you for your purchase of {item_name}.'
    recipients = [user_email]

    message = Message(subject=subject, body=body, recipients=recipients)

    try:
        mail.send(message)
        return True
    except Exception as e:
        print(f"An error occurred while sending the email: {e}")
        return False


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_owner = db.Column(db.Boolean, default=False)
    items = db.relationship('Item', backref='author', lazy=True)
    reset_token = db.Column(db.String(100), unique=True)

    news_articles = db.relationship('News', lazy=True)  # Added relationship backref

    def __init__(self, username, password, email):  # Updated constructor
        self.username = username
        self.password_hash = generate_password_hash(password, method='pbkdf2', salt_length=8)
        self.email = email  # Set the email field

    def check_password(self, password):
        if self.password_hash is None:
            return False

        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        return serializer.dumps(self.id)

    @staticmethod
    def verify_reset_token(token):
        try:
            user_id = serializer.loads(token, max_age=3600)  # Token expires after 1 hour
            return User.query.get(user_id)
        except ValueError:
            return None


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


app.app_context().push()
db.create_all()


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# Define the form for adding news
class AddNewsForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Perform the login logic here
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Login successful
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home', logged_in=True))
        else:
            # Login unsuccessful
            flash('Invalid username or password', 'danger')

    # Render the login page
    return render_template('login.html', logged_in=False)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Process registration form data
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        # Perform validation and registration logic
        if password != confirm_password:
            error_message = "Passwords do not match."
            return render_template('registration.html', error_message=error_message)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error_message = "Username already exists."
            return render_template('registration.html', error_message=error_message)

        new_user = User(username=username, password=password, email=email)

        db.session.add(new_user)

        send_user_created_email(email)

        db.session.commit()

        login_user(new_user)

        flash("Registration successful!", 'success')

        return redirect(url_for('login'))

    return render_template('registration.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate and send the password reset email
            token = user.generate_reset_token()
            reset_link = url_for('reset_password', token=token, _external=True)
            send_password_reset_email(user.email, reset_link)

            flash('An email with instructions to reset your password has been sent.')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2', salt_length=8)
        user.password_hash = hashed_password
        user.reset_token = None
        db.session.commit()
        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form, token=token)


@app.route('/')
def home():
    items = Item.query.all()
    admin = current_user.is_authenticated and current_user.is_admin
    owner = current_user.is_authenticated and current_user.is_owner
    return render_template('home.html', items=items, admin=admin, owner=owner)


@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        # Retrieve the item details from the form
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        image_file = request.files['image_file']
        stock = int(request.form['stock'])

        # Save the uploaded file
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        saved_filename = filename

        # Rotate and resize the image
        with Image.open(image_path) as img:
            if hasattr(img, '_getexif') and img._getexif() is not None:
                for orientation in ExifTags.TAGS.keys():
                    if ExifTags.TAGS[orientation] == 'Orientation':
                        exif = dict(img._getexif().items())
                        if orientation in exif:
                            if exif[orientation] == 3:
                                img = img.rotate(180, expand=True)
                            elif exif[orientation] == 6:
                                img = img.rotate(270, expand=True)
                            elif exif[orientation] == 8:
                                img = img.rotate(90, expand=True)
                            break

            # Resize the image to 200x200 pixels
            resized_image = img.resize((200, 200))
            resized_filename = f"resized_{secrets.token_hex(12)}_{filename}"
            resized_image_path = os.path.join(app.config['UPLOAD_FOLDER'], resized_filename)
            resized_image.save(resized_image_path)

        # Create the new item in the database
        author = current_user  # Assuming you're using Flask-Login and the current user is logged in
        item = Item.create_item(name=name, description=description, price=price, image_file=saved_filename,
                                author=author, stock=stock)

        # Redirect to the item details page
        return redirect(url_for('product_details', item_id=item.id))
    else:
        # Render the add item form template
        return render_template('add_item.html')


@app.route('/buy_item/<int:item_id>', methods=['POST'])
@login_required
def buy_item(item_id):
    # Retrieve the item from the database
    item = Item.query.get_or_404(item_id)

    # Check if the item is in stock
    if item.stock <= 0:
        flash('This item is currently out of stock.', 'danger')
        return redirect(url_for('product_details', item_id=item.id))

    # Reduce the stock count by 1 and record the sale
    item.stock -= 1
    sale = Sales(item_id=item_id, buyer_id=current_user.id, quantity=1, total_value=item.price)
    db.session.add(sale)

    db.session.commit()

    # Send email notification to the user
    send_purchase_email(current_user.email, item.name)

    flash('Item purchased successfully!', 'success')
    return redirect(url_for('product_details', item_id=item.id))




def resize_image(image_path, size):
    image = Image.open(image_path)
    image.thumbnail(size)
    return image


@app.route('/products')
def products():
    # Retrieve the products from the database
    products = Item.query.all()
    return render_template('products.html', products=products)


from random import sample


@app.route('/product/<int:item_id>')
def product_details(item_id):
    # Retrieve the item from the database by ID
    item = Item.query.get_or_404(item_id)

    # Retrieve 3 random other products
    other_products = Item.query.filter(Item.id != item_id).all()
    random_products = sample(other_products, 3)

    return render_template('product_details.html', item=item, random_products=random_products)


@app.route('/edit_product/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_product(item_id):
    # Retrieve the product from the database
    item = Item.query.get_or_404(item_id)

    # Check if the current user is the owner of the item or an admin
    if item.author != current_user and not current_user.is_admin:
        flash('You do not have permission to edit this item.', 'danger')
        return redirect(url_for('product_details', item_id=item.id))

    if request.method == 'POST':
        # Update the product details based on the submitted form data
        item.name = request.form['name']
        item.description = request.form['description']
        item.price = float(request.form['price'])
        item.stock = int(request.form['stock'])

        # Check if a new image file is uploaded
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file.filename != '':
                # Save the uploaded file
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                item.image_file = filename

        # Save the changes to the database
        db.session.commit()

        flash('Product updated successfully!', 'success')
        return redirect(url_for('product_details', item_id=item.id))

    # Render the edit product template with the product details
    return render_template('edit_product.html', item=item)


@app.route('/delete_product/<int:item_id>', methods=['POST'])
@login_required
def delete_product(item_id):
    # Retrieve the product from the database
    item = Item.query.get_or_404(item_id)

    # Delete the product from the database
    render_template('delete_product.html', item=item)
    db.session.delete(item)
    db.session.commit()

    flash('Product deleted successfully!', 'success')
    return redirect(url_for('products'))


@app.route('/profile')
def profile():
    return render_template('profile.html')


# Route for adding news
@app.route('/add_news', methods=['GET', 'POST'])
@admin_required
@login_required
def add_news():
    form = AddNewsForm()

    if form.validate_on_submit():
        # Process the submitted form data
        title = form.title.data
        content = form.content.data
        author = current_user

        # Create a new News object
        news = News(title=title, content=content, author_id=author.id)

        # Add the news to the database
        db.session.add(news)
        db.session.commit()

        return redirect(url_for('news'))

    return render_template('add_news.html', form=form)


@app.route('/news/edit/<int:news_id>', methods=['GET', 'POST'])
@admin_required
def edit_news(news_id):
    news_article = News.query.get(news_id)

    if not news_article:
        # Handle the case where the news article does not exist
        # Redirect or show an error message
        return redirect(url_for('news'))

    if request.method == 'POST':
        # Retrieve the updated data from the form
        title = request.form.get('title')
        content = request.form.get('content')

        # Update the news article with the new data
        news_article.title = title
        news_article.content = content

        # Commit the changes to the database
        db.session.commit()

        # Redirect to the news article page or any other appropriate page
        return redirect(url_for('news', news_id=news_id))

    # Render the edit news template with the news article data
    return render_template('edit_news.html', news_article=news_article)


@app.route('/news/delete/<int:news_id>', methods=['GET', 'POST'])
@admin_required
def delete_news(news_id):
    news_article = News.query.get(news_id)

    if not news_article:
        # Handle the case where the news article does not exist
        # Redirect or show an error message
        return redirect(url_for('news'))

    # Delete the news article from the database
    db.session.delete(news_article)
    db.session.commit()

    # Redirect to the news page or any other appropriate page
    return redirect(url_for('news'))


@app.route('/news')
def news():
    news_articles = News.query.all()
    admin = current_user.is_authenticated and current_user.is_admin
    owner = current_user.is_authenticated and current_user.is_owner
    return render_template('news.html', news_articles=news_articles, admin=admin, owner=owner)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/admin_page')
@login_required
def admin_page():
    if current_user.is_admin:  # Assuming you have an `is_admin` attribute in your `User` model
        products = Item.query.all()
        users = User.query.all()
        admin_users = User.query.filter_by(is_admin=True).all()
        return render_template('admin_page.html', products=products, users=users, admin_users=admin_users)
    else:
        flash('Access denied. You need to be an admin to access this page.', 'danger')
        return redirect(url_for('home'))


@app.route('/add_admin', methods=['POST'])
@login_required
def add_admin():
    if current_user.is_owner:  # Check if the current user is the owner
        admin_id = request.form.get('admin_id')

        user = User.query.get(admin_id)
        if user:
            user.is_admin = True
            db.session.commit()
            flash('Admin added successfully!', 'success')
        else:
            flash('User not found.', 'danger')
    else:
        flash('You do not have permission to add an admin.', 'danger')

    return redirect(url_for('admin_page'))


@app.route('/remove_admin', methods=['POST'])
@login_required
def remove_admin():
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')

        if current_user.is_owner:  # Check if the current user is the owner
            admin = User.query.filter_by(id=admin_id, is_admin=True).first()

            if admin:
                admin.is_admin = False
                db.session.commit()

                flash("Admin removed successfully!", 'success')
            else:
                flash("Admin not found.", 'danger')
        else:
            flash("You do not have permission to remove an admin.", 'danger')

    return redirect(url_for('admin_page'))


@app.route('/admin/products')
def manage_products():
    # Retrieve the list of products from the database
    products = Item.query.all()

    return render_template('manage_products.html', products=products)


@app.route('/sales_report')
@admin_required
def sales_report():
    # Retrieve the sales data from the database grouped by month
    sales_data_monthly = db.session.query(
        Item.author_id,
        extract('month', Item.sale_date),
        func.count(Item.id),
        func.sum(Item.price)
    ).group_by(Item.author_id, extract('month', Item.sale_date)).all()

    # Retrieve the top-selling items per month
    top_selling_items = db.session.query(
        extract('month', Item.sale_date),
        Item.name,
        func.count(Item.id)
    ).group_by(extract('month', Item.sale_date), Item.name).all()

    # Prepare the data for the CSV file
    data = []
    monthly_sales = defaultdict(list)
    for user_id, month, item_count, total_value in sales_data_monthly:
        user = User.query.get(user_id)
        username = user.username if user else "Unknown User"
        monthly_sales[month].append([username, item_count, total_value])

    # Write the top-selling items data
    top_selling = defaultdict(list)
    for month, item_name, count in top_selling_items:
        top_selling[month].append([item_name, count])

    # Create a temporary file to store the CSV data
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as file:
        temp_file = file.name

        # Write the data to the CSV file
        writer = csv.writer(file)
        writer.writerow(
            ['Month', 'Username', 'Number of Items Sold', 'Total Value', 'Top Selling Item', 'Quantity Sold'])

        for month in monthly_sales:
            for row in monthly_sales[month]:
                top_item = max(top_selling[month], key=lambda x: x[1]) if month in top_selling else ["N/A", "N/A"]
                writer.writerow([month] + row + top_item)

    # Send the file as a response to the user
    response = send_file(temp_file, mimetype='text/csv', as_attachment=True)

    # Set the Content-Disposition header to specify the attachment filename
    filename = 'sales_report.csv'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

    return response


@app.route('/chat')
def chat():
    return render_template('chat.html')


if __name__ == '__main__':
    app.run(debug=True)
