from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime
import os
import uuid
from .database import db

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'cases'

db.init_app(app)

# Import routes after app initialization
from .routes import main_routes, case_routes, analysis_routes

app.register_blueprint(main_routes.bp)
app.register_blueprint(case_routes.bp)
app.register_blueprint(analysis_routes.bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)