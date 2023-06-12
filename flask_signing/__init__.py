__name__ = "flask_signing"
__author__ = "Sig Janoska-Bedi"
__credits__ = ["Sig Janoska-Bedi",]
__version__ = "0.2.0"
__license__ = "BSD-3-Clause"
__maintainer__ = "Sig Janoska-Bedi"
__email__ = "signe@atreeus.com"

import datetime, secrets
from flask_sqlalchemy import SQLAlchemy
from typing import Union, List, Dict, Any

class Signatures:
    """
    The Signatures class handles operations related to the creation, management, and validation 
    of signing keys in the database.
    """
    
    def __init__(self, app, byte_len:int=24):
        """
        Initializes a new instance of the Signatures class.

        Args:
            app (Flask): A flask object to contain the context for database interactions. 
            byte_len (int, optional): The length of the generated signing keys. Defaults to 24.
        """

        self.db = SQLAlchemy(app)
        self.Signing = self.get_model()
        self.db.create_all()  # this will create all necessary tables

        # self.db = database
        self.byte_len = byte_len

    def generate_key(self, length:int=None) -> str:
        """
        Generates a signing key with the specified byte length. 
        Note: byte length generally translates to about 1.3 times as many chars,
        see https://docs.python.org/3/library/secrets.html.

        Args:
            length (int, optional): The length of the generated signing key. Defaults to None, in which case the byte_len is used.

        Returns:
            str: The generated signing key.
        """

        if not length: 
            length = self.byte_len
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
        Signing = self.get_model()

        # loop until a unique key is generated
        while True:
            key = self.generate_key()
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

        Signing = self.get_model()

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

        Signing = self.get_model()


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

    def get_model(self):

        """
        Generate an instance of the Signing class, which represents the Signing table in the database.

        Each instance of this class represents a row of data in the database table.

        Attributes:
            signature (str): The primary key of the Signing table. This field is unique for each entry.
            email (str): The email associated with a specific signing key.
            scope (str): The scope within which the key is valid.
            active (bool): The status of the signing key. If True, the key is active.
            timestamp (datetime): The date and time when the signing key was created.
            expiration (datetime): The date and time when the signing key is set to expire.
        """

        if not hasattr(self, '_model'):
            class Signing(self.db.Model):
                __tablename__ = 'signing'
                signature = self.db.Column(self.db.String(1000), primary_key=True) 
                email = self.db.Column(self.db.String(100))
                scope = self.db.Column(self.db.String(100))
                active = self.db.Column(self.db.Boolean)
                timestamp = self.db.Column(self.db.DateTime, nullable=False, default=datetime.datetime.utcnow)
                expiration = self.db.Column(self.db.DateTime, nullable=False, default=datetime.datetime.utcnow)

            self._model = Signing

        return self._model


    def query_keys(self, active:bool=None, scope:str=None, email:str=None) -> Union[List[Dict[str, Any]], bool]:
        """
        Query signing keys by active status, scope, and email.

        This function returns a list of signing keys that match the provided parameters.
        If no keys are found, it returns False.

        Args:
            active (bool, optional): The active status of the signing keys. Defaults to None.
            scope (str, optional): The scope of the signing keys. Defaults to None.
            email (str, optional): The email associated with the signing keys. Defaults to None.

        Returns:
            Union[List[Dict[str, Any]], bool]: A list of dictionaries where each dictionary contains the details of a signing key,
            or False if no keys are found.
        """

        Signing = self.get_model()

        query = Signing.query

        if active is not None:
            query = query.filter(Signing.active == active)
        if scope:
            query = query.filter(Signing.scope == scope)
        if email:
            query = query.filter(Signing.email == email)

        result = query.all()

        if not result:
            return False

        return [{'signature': key.signature, 'email': key.email, 'scope': key.scope, 'active': key.active, 'timestamp': key.timestamp, 'expiration': key.expiration} for key in result]