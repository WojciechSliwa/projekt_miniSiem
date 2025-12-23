# app/blueprints/ui.py
from flask import Blueprint, render_template
from flask_login import login_required

ui_bp = Blueprint('ui', __name__)

@ui_bp.route('/')
def index():
    # To jest teraz Dashboard Monitoringu
    return render_template('index.html')

@ui_bp.route('/config')
def config():
    # To jest nowa strona administracyjna
    return render_template('config.html')