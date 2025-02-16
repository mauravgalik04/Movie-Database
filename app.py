from flask import Flask, render_template, redirect, request, url_for, flash 
from flask_sqlalchemy import SQLAlchemy 
import os 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user 
from flask_bcrypt import Bcrypt 
from werkzeug.utils import secure_filename
from functools import wraps

basedir = os.path.abspath(os.path.dirname(__file__)) 
app = Flask(__name__) 
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" +  os.path.join(basedir, "app.db") 
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config["SECRET_KEY"] = "Your_secret_key" 
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app) 
bcrypt = Bcrypt(app) 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login" 

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class Movie(db.Model , UserMixin):
    __tablename__ = "movie"
    sno = db.Column(db.Integer , primary_key = True , autoincrement = True)
    name = db.Column(db.String(100) )
    release_year = db.Column(db.Integer )
    imdb_rating = db.Column(db.Float )
    genre = db.Column(db.String )
    description = db.Column(db.String(200) ) 
    cast = db.Column(db.String(100) )
    poster = db.Column(db.String(2000) )
    landscape = db.Column(db.String(2000) )

class User(db.Model , UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer , primary_key = True)
    username = db.Column(db.String(50) , nullable = False)
    email = db.Column(db.String(50) , nullable =True ,unique = True)
    password_hash = db.Column(db.String(100) , nullable =False)
    role = db.Column(db.String(50), nullable=False, default="user") 
    def set_password(self, password): 
        self.password_hash = bcrypt.generate_password_hash(password) 
    def check_password(self, password): 
        return bcrypt.check_password_hash(self.password_hash, password)
@login_manager.user_loader
def load_user(user_id): 
    return db.session.get(User, int(user_id))

def admin_required(func): 
    @wraps(func) 
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin': 
            flash("Access denied!", "danger") 
            return redirect(url_for('landing'))
        return func(*args, **kwargs) 
    return wrapper 
with app.app_context(): 
    db.create_all()
    if not User.query.filter_by(role="admin").first():
        admin11  = User(username = "movieAdmin" , email = "admin24@gmail.com" ,role = "admin" ) 
        admin11.set_password('adminkey24')
        db.session.add(admin11)
        db.session.commit()  
@app.route("/") 
def landing(): 
    return render_template("index.html") 


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
            return redirect(url_for("landing")) 
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
        new_user = User(username=name, email=email) 
        new_user.set_password(password)
        db.session.add(new_user) 
        db.session.commit() 
        flash("Registration successful! Please log in.", "success") 
        return redirect(url_for("login")) 
    return render_template("/register.html") 


@app.route("/logout") 
@login_required 
def logout(): 
    logout_user() 
    flash("Logged out successfully!", "info")
    return redirect(url_for("landing")) 


@app.route("/profile") 
@login_required 
def profile(): 
    return render_template("profile.html")

@app.route('/add_movie', methods = ['POST' ,'GET'])
@admin_required
def addMovie():
    if request.method == 'POST':
        name = request.form.get('movie-name')
        year = request.form.get('release-year')
        genre = request.form.get('genre')
        story = request.form.get('movie-description')
        cast = request.form.get('movie-cast')
        rating = request.form.get('imdb-rating')
        poster = request.files['poster']
        landscape = request.files['landscape']

        # Save poster file
        poster_filename = secure_filename(poster.filename)
        poster_path = os.path.join(app.config['UPLOAD_FOLDER'], poster_filename)
        poster.save(poster_path)

        # Save landscape file
        landscape_filename = secure_filename(landscape.filename)
        landscape_path = os.path.join(app.config['UPLOAD_FOLDER'], landscape_filename)
        landscape.save(landscape_path)        

        new_movie = Movie(name = name , release_year = year , genre = genre , description = story , imdb_rating = rating , cast = cast , poster = poster_filename ,landscape = landscape_filename)
        db.session.add(new_movie)
        db.session.commit()
        flash("Movie added Succesfully" , "info")
    return render_template('add-movie.html')
@app.route('/movies')
def showMovies():
    movies = Movie.query.all()
    return render_template('showMovies.html', movies=movies)

@app.route('/update/<int:sno>' , methods = ['POST' ,'GET'])
@admin_required
def update_movie(sno):
    movie = Movie.query.get(sno)
    if request.method =="POST":
        movie.name = request.form.get('movie-name')
        movie.year = request.form.get('release-year')
        movie.genre = request.form.get('genre')
        movie.story = request.form.get('movie-description')
        movie.cast = request.form.get('movie-cast')
        movie.rating = request.form.get('imdb-rating')
        db.session.commit()
        return redirect(url_for('showMovies'))
    return render_template('update_movie.html' , movie = movie)
@app.route('/delete/<int:sno>')
@admin_required
def delete_movie(sno):
    movie = Movie.query.get(sno)
    db.session.delete(movie)
    db.session.commit()
    return redirect(url_for('showMovies'))

@app.route('/movies/<int:sno>')
def featured_movie(sno):
    movie = Movie.query.get(sno)
    return render_template('feature-movie.html' , movie = movie)

if __name__=="__main__":
    app.run(debug=True)