""" 
models.py: defining the Signing key model 
"""

__name__ = "flask_signing.models"
__author__ = "Sig Janoska-Bedi"
__credits__ = ["Sig Janoska-Bedi",]
__version__ = "0.1.0"
__license__ = "BSD-3-Clause"
__maintainer__ = "Sig Janoska-Bedi"
__email__ = "signe@atreeus.com"

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Signing(db.Model):
    """
    The Signing class represents the Signing table in the database.

    Each instance of this class represents a row of data in the database table.

    Attributes:
        signature (str): The primary key of the Signing table. This field is unique for each entry.
        email (str): The email associated with a specific signing key.
        scope (str): The scope within which the key is valid.
        active (bool): The status of the signing key. If True, the key is active.
        timestamp (datetime): The date and time when the signing key was created.
        expiration (datetime): The date and time when the signing key is set to expire.
    """
    __tablename__ = 'signing'
    signature = db.Column(db.String, primary_key=True) 
    email = db.Column(db.String(100))
    scope = db.Column(db.String(100))
    active = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expiration = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
