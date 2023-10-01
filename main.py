
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from waitress import serve
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_manager
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager


def search(keyword):
    results = []
    items = Item.query.all()  # Используйте SQLAlchemy для получения всех записей из таблицы Item
    item_names = [item.name for item in items]
    a = process.extractOne(keyword, item_names)
    results.append(a)
    return results


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aeroports.db'
# db.init_app(app) # я не понимаю надо оно или не надо
db = SQLAlchemy(app)

app.secret_key='some'
login_manager = LoginManager(app)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    raic = db.Column(db.String(8), unique=True)
    coordinate_x = db.Column(db.String(120), nullable=True)
    coordinate_y = db.Column(db.String(120), nullable=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable = False,unique = True)
    password = db.Column(db.String(255), nullable = False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    items = Item.query.all()
    return render_template('index.html', api_key='33fbe2d1-b0dc-4315-bbf5-cc57da1dbe8f', items=items)


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_route():
    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()  # Получите значение ключевого слова из формы, удалите пробелы
        items = Item.query.all()  # Получите все записи из таблицы Item

        if not keyword:  # Если ключевое слово отсутствует или пустое
            return render_template('index.html', results=items, keyword=keyword)

        results = Item.query.filter(Item.name.ilike(
            f"%{keyword}%")).all()

        return render_template('index.html', results=results, keyword=keyword)

    return render_template('index.html')


@app.route('/create', methods=['POST', 'GET'])
@login_required
def create():
    if request.method == 'POST':
        name = request.form['name']
        raic = request.form['raic']
        coordinate_x = request.form['coordinate_x']
        coordinate_y = request.form['coordinate_y']
        aer = Item(name=name, raic=raic, coordinate_x=coordinate_x, coordinate_y=coordinate_y)

        db.session.add(aer)
        db.session.commit()
        return render_template('create.html')
    else:
        return render_template('create.html')



@app.route('/login',methods = ['GET','POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
       user = User.query.filter_by(login = login).first()
       if user and check_password_hash(user.password, password):
           login_user(user)
           return render_template('create.html')
       else:
           flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Please, fill all fields!')
        elif password != password2:
            flash('Passwords are not equal!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))

    return render_template('register.html')



@app.route('/logout',methods = ['GET','POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next' + request.url)
    return response


if __name__ == '__main__':
    app.run(debug=True)
    serve(app, host="0.0.0.0", port=8080)
