__name__ = "flask_signing"
__author__ = "Sig Janoska-Bedi"
__credits__ = ["Sig Janoska-Bedi",]
__version__ = "0.1.0"
__license__ = "AGPL-3.0"
__maintainer__ = "Sig Janoska-Bedi"
__email__ = "signe@atreeus.com"

import os, datetime, secrets, threading, time, functools
from flask import current_app, flash, redirect, url_for, abort
from flask_signing.models import Signing, db


class Signatures:
    """
    The Signatures class handles operations related to the creation, management, and validation 
    of signing keys in the database.
    """

    def __init__(self, database=db, key_len:int=24):
        """
        Initializes a new instance of the Signatures class.

        Args:
            database (SQLAlchemy, optional): An SQLAlchemy object for database interactions. 
                Defaults to the db object imported from flask_signing.models.
            key_len (int, optional): The length of the generated signing keys. Defaults to 24.
        """
        self.db = database
        self.key_len = key_len

    def generate_key(self, length:int=24) -> str:
        """
        Generates a signing key with the specified length.

        Args:
            length (int, optional): The length of the generated signing key. Defaults to 24.

        Returns:
            str: The generated signing key.
        """

        return secrets.token_urlsafe(length)

    def write_key_to_database(self, scope:str=None, expiration:int=1, active:bool=True, email:str=None) -> str:
        """
        Writes a newly generated signing key to the database.

        This function will continuously attempt to generate a key until a unique one is created. 

        Args:
            scope (str): The scope within which the signing key will be valid. Defaults to None.
            expiration (int, optional): The number of hours after which the signing key will expire. 
                If not provided or equals 0, the expiration will be set to zero. Defaults to 1.
            active (bool, optional): The status of the signing key. Defaults to True.
            email (str, optional): The email associated with the signing key. Defaults to None.

        Returns:
            str: The generated and written signing key.
        """

        # loop until a unique key is generated
        while True:
            key = self.generate_key(length=self.key_len)
            if not Signing.query.filter_by(signature=key).first(): break

        new_key = Signing(
                        signature=key, 
                        scope=scope.lower() if scope else "",
                        email=email.lower() if email else "", 
                        active=active,
                        expiration=(datetime.datetime.utcnow() + datetime.timedelta(hours=expiration)) if expiration else 0,
                        timestamp=datetime.datetime.utcnow(),
        )

        self.db.session.add(new_key)
        self.db.session.commit()

        return key

    def expire_key(self, key):

        """
        Expires a signing key in the database.

        This function finds the key in the database and disables it by setting its 'active' status to False.
        If the key does not exist, the function returns False and an HTTP status code 500.

        Args:
            key (str): The signing key to be expired.

        Returns:
            tuple: A tuple containing a boolean value indicating the success of the operation, and an HTTP status code.
        """
        signing_key = Signing.query.filter_by(signature=key).first()
        if not signing_key:
            return False

        # This will disable the key
        signing_key.active = False
        self.db.session.commit()
        return True

    def verify_signature(self, signature, scope):
        """
        Verifies the validity of a given signing key against a specific scope.

        This function checks if the signing key exists, if it is active, if it has not expired,
        and if its scope matches the provided scope. If all these conditions are met, the function
        returns True, otherwise, it returns False.

        Args:
            signature (str): The signing key to be verified.
            scope (str): The scope against which the signing key will be validated.

        Returns:
            bool: True if the signing key is valid and False otherwise.
        """

        signing_key = Signing.query.filter_by(signature=signature).first()

        # if the key doesn't exist
        if not signing_key:
            return False

        # if the signing key's expiration time has passed
        if signing_key.expiration < datetime.datetime.utcnow():
            self.expire_key(signature)
            return False

        # if the signing key is set to inactive
        if not signing_key.active:
            return False

        # if the signing key's scope doesn't match the required scope
        if signing_key.scope != scope:
            return False

        return True


