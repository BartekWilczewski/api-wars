from flask import Flask, render_template, redirect, request, url_for, request, session, flash
import data_handler
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route('/')
@app.route('/<user>')
def main(user=None):
    return render_template('index.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = data_handler.get_users()
        password = request.form.get('reg-password')
        password_again = request.form.get('reg-password-again')
        if password == '' or password_again == '':
            flash('Please enter a password')
            return redirect(url_for('register'))
        elif password == password_again:
            user_email = request.form.get('reg-email')
            if user_email == '':
                flash('Please enter your email address')
                return redirect(url_for('register'))
            first_name = request.form.get('first-name')
            last_name = request.form.get('last-name')
            if first_name != '' and last_name != '':
                if user_email in users[0]['username']:
                    flash('Email already in use')
                    return redirect(url_for('register'))
                else:
                    hashed_password = data_handler.hash_password(password)
                    data_handler.register_user(user_email, first_name, last_name, hashed_password)
                    user_id = data_handler.get_user_id(user_email)['id']
                    session['username'] = user_email
                    session['user_id'] = user_id
                    return redirect(url_for('main'))
            else:
                flash('Please enter a name', 'info')
                return redirect(url_for('register'))
        else:
            flash("Password doesn't match", 'info')
            return redirect(url_for('register'))
    elif "username" in session:
        flash('Already logged in')
        return redirect(url_for('main'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session:
        return redirect(url_for('main'))
    if request.method == 'POST':
        usernames = [data['username'] for data in data_handler.get_users()]
        username = request.form['username']
        input_password = request.form['password']
        if username in usernames:
            password = data_handler.get_password_by_username(username)['password']
            if data_handler.verify_password(input_password, password):
                user_id = data_handler.get_user_id(username)['id']
                session['username'] = username
                session['user_id'] = user_id
                return redirect(url_for('main', user=session['username']))
            else:
                return render_template('login.html', error="password")
        else:
            return render_template('login.html', error="user")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main'))


if __name__ == "__main__":
    app.run()