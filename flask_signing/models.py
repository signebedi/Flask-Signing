""" 
models.py: defining the models 
"""

__name__ = "flask_signing.models"
__author__ = "Sig Janoska-Bedi"
__credits__ = ["Sig Janoska-Bedi",]
__version__ = "0.1.0"
__license__ = "AGPL-3.0"
__maintainer__ = "Sig Janoska-Bedi"
__email__ = "signe@atreeus.com"

from flask import current_app
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Signing(db.Model):
    __tablename__ = 'signing'
    signature = db.Column(db.String, primary_key=True) 
    email = db.Column(db.String(100))
    scope = db.Column(db.String(100))
    active = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expiration = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # timestamp = db.Column(db.Float)
    # expiration = db.Column(db.Float)