from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from markupsafe import Markup
import requests
import os
import pandas as pd
from dotenv import load_dotenv
import json

load_dotenv()  # Load environment variables from .env file
CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

directory = "raw_data"
ALLOWED_EMAILS = {os.path.splitext(filename)[0] for filename in os.listdir(directory) if filename.endswith('.csv')}

app = Flask(__name__)
app.secret_key = os.urandom(24)

# SQLite database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(db.Model, UserMixin):
    id = db.Column(db.String(120), primary_key=True)
    currently_labeling = db.Column(db.Integer(), nullable=False)
    completed = db.Column(db.Integer(), nullable=False)

    def __init__(self, email):
        self.id = email
        self.currently_labeling = 0
        self.completed = 0


def load_user(email):
    if email in ALLOWED_EMAILS:
        user = db.session.get(User, email)
        if user:
            return user
        else:
            new_user = User(email)
            db.session.add(new_user)
            db.session.commit()
            return new_user
    return None


def remove_trailing_backslashes(s):
    while s.endswith('\\'):
        s = s[:-1]
    return s


def render_unicode_text(text):
    # Replace escaped newlines with HTML line breaks
    text = remove_trailing_backslashes(text)
    text = text.replace('\\n', '<br>')

    try:
        text = json.loads(f'"{text}"')  # first try JSON decode
    except json.decoder.JSONDecodeError as e:
        try:
            text = text.encode('latin1').decode('unicode-escape')  # JSON failed, maybe still interpretable by unicode
        except Exception as e:  # hopeless
            text = f'Encountered error: {e}. Please find the raw text below: <br> {text}'
    return Markup(text)


@login_manager.user_loader
def user_loader(email):
    return load_user(email)


@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403


@app.route('/')
def index():
    if current_user.is_authenticated:
        user = db.session.get(User, current_user.id)
        user_id = current_user.id
        csv_path = f'raw_data/{user_id}.csv'
        labeled_csv_path = f'labeled_data/{user_id}.csv'

        # Check if there's already a labeled data file
        if os.path.exists(labeled_csv_path):
            df = pd.read_csv(labeled_csv_path)
        else:
            df = pd.read_csv(csv_path)

        if user.currently_labeling >= len(df):
            user.completed = 1
            db.session.commit()
            return render_template("completed.html")
        current_index = user.currently_labeling + df['Index'].iloc[0]
        text_paragraph = df[df['Index'] == current_index]['Post'].values[0]
        l = len(df)
        del df

        return render_template('index.html', text_paragraph=render_unicode_text(text_paragraph),
                               current_task=user.currently_labeling + 1,
                               total_task=l,
                               email=current_user.id)
    else:
        return render_template('login.html', client_id=CLIENT_ID)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.json['auth_code']
        try:
            idinfo = requests.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}")
            idinfo = idinfo.json()
            if idinfo["aud"] == CLIENT_ID:
                user_email = idinfo['email']
                if user_email in ALLOWED_EMAILS:
                    user = load_user(user_email)
                    login_user(user)
                    return jsonify({'result': 'success'})
                else:
                    return jsonify({'result': 'not_allowed'})
            else:
                return jsonify({'result': 'failure'})
        except Exception as e:
            raise e
    return render_template('login.html')


@app.route('/label', methods=['POST'])
@login_required
def label():
    label = request.form['label']
    user_id = current_user.get_id()
    labeled_csv_path = f'labeled_data/{user_id}.csv'

    # Load existing data
    if os.path.exists(labeled_csv_path):
        df = pd.read_csv(labeled_csv_path)
    else:
        df = pd.read_csv(f'raw_data/{user_id}.csv')
        df['Label'] = None

    user = db.session.get(User, current_user.id)

    # Update label
    current_index = user.currently_labeling + df['Index'].iloc[0]
    df.loc[df['Index'] == current_index, 'Label'] = int(label)
    user.currently_labeling += 1
    db.session.commit()
    df.to_csv(labeled_csv_path, index=False)
    del df

    return jsonify({'result': 'success'})


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect("/")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the tables in your database
    app.run(debug=True, ssl_context='adhoc')
