from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User
from app.forms import LoginForm

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ui.config'))

    form = LoginForm()

    if form.validate_on_submit():
        # TODO: ZADANIE 1 - LOGOWANIE
        # 1. Pobierz użytkownika z bazy danych na podstawie form.username.data
        # 2. Sprawdź hasło używając metody user.check_password(form.password.data)
        # 3. Jeśli poprawne:
        #    - użyj funkcji login_user(user)
        #    - wyświetl flash('Zalogowano pomyślnie!', 'success')
        #    - przekieruj do ui.config
        # 4. Jeśli błędne:
        #    - wyświetl flash('Błąd logowania', 'danger')
        
        flash('Mechanizm logowania nie jest jeszcze zaimplementowany!', 'warning')
        # pass

    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Zostałeś wylogowany.', 'info')
    return redirect(url_for('ui.index'))