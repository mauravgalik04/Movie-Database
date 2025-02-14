from flask import Flask, render_template, redirect, request, url_for, flash 
from flask_sqlalchemy import SQLAlchemy 
import os 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user 
from flask_bcrypt import Bcrypt 
basedir = os.path.abspath(os.path.dirname(__file__)) 
app = Flask(__name__) 
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" +  os.path.join(basedir, "app.db") 
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config["SECRET_KEY"] = "Your_secret_key" 
db = SQLAlchemy(app) 
bcrypt = Bcrypt(app) 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login" 
class Movie(db.Model , UserMixin):
    __tablename__ = "movie"
    sno = db.Column(db.Integer , primary_key = True)
    name = db.Column(db.String(100) , nullable  = False)
    release_year = db.Column(db.Integer , nullable = False)
    imbd_rating = db.Column(db.Float , nullable = True)
    genre = db.Column(db.String , nullable = False)
    descripion = db.Column(db.String(1000) , nullable = False) 
    cast = db.Column(db.String(100) , nullable = False)
    poster = db.Column(db.String(2000) , nullable=False)
    landscape = db.Column(db.String(2000) , nullable = False)

class User(db.Model , UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer , primary_key = True)
    username = db.Column(db.String(50) , nullable = False)
    password_hash = db.Column(db.String(100) , nullable =False)
    role = db.Column(db.String(50), nullable=False, default="user") 
    def set_password(self, password): 
        self.password_hash = bcrypt.generate_password_hash(password) 
    def check_password(self, password): 
        return bcrypt.check_password_hash(self.password_hash, password) 
@login_manager.user_loader
def load_user(user_id): 
    return db.session.get(User, int(user_id)) 
with app.app_context(): 
    db.create_all() 
@app.route("/") 
def landing(): 
    return render_template("index.html") 


@app.route("/home") 
@login_required 
def home():
    return render_template("home.html") 


@app.route("/login", methods=["GET", "POST"]) 
def login(): 
    if request.method == "POST": 
        email = request.form.get("email") 
        password = request.form.get("password") 
        role = request.form.get("role") 
        user = User.query.filter_by(email=email, role=role).first() 
        if user and user.check_password(password): 
            login_user(user) 
            flash("Login successful!", "success") 
            return redirect(url_for("dashboard")) 
        else: 
            flash("Invalid credentials!", "danger") 
    return render_template("login.html") 


@app.route("/register", methods=["GET", "POST"]) 
def register(): 
    if request.method == "POST": 
        name = request.form.get("name") 
        email = request.form.get("email") 
        password = request.form.get("password") 
        confirm_password = request.form.get("confirm_password") 
         # Check if passwords match 
        if password != confirm_password: 
            flash("Passwords do not match!", "danger") 
            return redirect(url_for("register")) # Check if the email already exists 
        if User.query.filter_by(email=email).first(): 
            flash("Email already exists!", "danger")
            return redirect(url_for("register")) 
        new_user = User(name=name, email=email) 
        new_user.set_password(password)
        # admin11  = User(name = "gaurav-malik-123" , email = "gauravadmin@gmail.com" , password_hash = set_password("admin123") ,mobile = 9024001139 ,role = "admin" ) 
        db.session.add(new_user) 
        # db.session.add(admin11)
        db.session.commit() 
        flash("Registration successful! Please log in.", "success") 
        return redirect(url_for("login")) 
    return render_template("/register.html") 


@app.route("/logout") 
@login_required 
def logout(): 
    logout_user() 
    flash("Logged out successfully!", "info")
    return redirect(url_for("login")) 


@app.route("/profile") 
@login_required 
def profile(): 
    return render_template("profile.html")



if __name__=="__main__":
    app.run(debug=True)