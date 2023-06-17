from .__metadata__ import (__name__, __author__, __credits__, __version__, 
                       __license__, __maintainer__, __email__)
import datetime, secrets
from functools import wraps
from sqlalchemy import func, literal
from sqlalchemy.exc import SQLAlchemyError
from flask_sqlalchemy import SQLAlchemy
from typing import Union, List, Dict, Any

class RateLimitExceeded(Exception):
    """
    An exception that is raised when the request count for a specific signature 
    exceeds the maximum allowed requests within a specified time period in the 
    Signatures class.

    This exception is used to signal that the rate limit has been exceeded, so the 
    calling code can catch this exception and handle it appropriately - for example,
    by sending an HTTP 429 Too Many Requests response to a client.
    """
    pass

class Signatures:
    """
    The Signatures class handles operations related to the creation, management, and validation 
    of signing keys in the database.
    """
    
    def __init__(self, app, safe_mode:bool=True, byte_len:int=24, rate_limiting=False, rate_limiting_max_requests=10, rate_limiting_period=datetime.timedelta(minutes=1)):
        """
        Initializes a new instance of the Signatures class.

        Args:
            app (Flask): A flask object to contain the context for database interactions. 
            safe_mode (bool, optional): If safe_mode is enabled, we will prevent rotation of disabled or rotated keys. Defaults to True.
            byte_len (int, optional): The length of the generated signing keys. Defaults to 24.
            rate_limiting (bool, optional): If rate_limiting is enabled, we will impose key-by-key rate limits. Defaults to False.
            rate_limiting_max_requests (int, optional): Maximum allowed requests per time period.
            rate_limiting_period (datetime.timedelta, optional): Time period for rate limiting. Defaults to 1 hour.
        """

        self.db = SQLAlchemy(app)
        self.Signing = self.get_model()
        self.db.create_all()  # this will create all necessary tables

        self.byte_len = byte_len

        # Set safe mode to prevent disabled/rotated keys from being rotated
        self.safe_mode = safe_mode

        # Set rate limiting attributes
        self.rate_limiting = rate_limiting
        self.rate_limiting_max_requests = rate_limiting_max_requests
        self.rate_limiting_period = rate_limiting_period

    class request_limiter:
        """
        A descriptor class that wraps a function with rate limiting logic. This descriptor is meant to 
        be used as a decorator for methods in the Signatures class.

        If rate limiting is enabled in the Signatures instance, this decorator checks the request count 
        for the provided signature and raises a `RateLimitExceeded` exception if the count exceeds 
        the max requests allowed in a set time period. 

        If the time period has passed since the last request, it resets the request count. If the request 
        count is within limits, it increments the request count and updates the time of the last request.

        If rate limiting is not enabled, the descriptor simply calls the original function.

        Args:
            func (Callable): The function to wrap with rate limiting logic.

        Returns:
            wrapper (Callable): The wrapped function which now includes rate limiting logic.
        """

        def __init__(self, func):
            self.func = func

        def __get__(self, instance, owner):
            @wraps(self.func)
            def wrapper(signature, *args, **kwargs):

                # If rate limiting has not been enabled, then we always return True
                if not instance.rate_limiting:
                    return self.func(instance, signature, *args, **kwargs)

                Signing = instance.get_model()

                signing_key = Signing.query.filter_by(signature=signature).first()

                # If the key does not exist
                if not signing_key:
                    return False

                # Reset request_count if period has passed since last_request_time
                if datetime.datetime.utcnow() - signing_key.last_request_time >= instance.rate_limiting_period:
                    signing_key.request_count = 0
                    signing_key.last_request_time = datetime.datetime.utcnow()

                # Check if request_count exceeds max_requests
                if signing_key.request_count >= instance.rate_limiting_max_requests:
                    raise RateLimitExceeded("Too many requests. Please try again later.")

                # If limit not exceeded, increment request_count and update last_request_time
                signing_key.request_count += 1
                signing_key.last_request_time = datetime.datetime.utcnow()

                instance.db.session.commit()

                return self.func(instance, signature, *args, **kwargs)
            return wrapper

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

    def write_key(self, scope:str=None, expiration:int=1, active:bool=True, email:str=None, previous_key:str=None) -> str:
        """
        Writes a newly generated signing key to the database.

        This function will continuously attempt to generate a key until a unique one is created. 

        Args:
            scope (str): The scope within which the signing key will be valid. Defaults to None.
            expiration (int, optional): The number of hours after which the signing key will expire. 
                If not provided or equals 0, the expiration will be set to zero. Defaults to 1.
            active (bool, optional): The status of the signing key. Defaults to True.
            email (str, optional): The email associated with the signing key. Defaults to None.
            previous_key (str, optional): The previous key to associate with this key, in the case of key rotation. Defaults to None.

        Returns:
            str: The generated and written signing key.
        """
        Signing = self.get_model()

        # loop until a unique key is generated
        while True:
            key = self.generate_key()
            if not Signing.query.filter_by(signature=key).first(): break

        # Convert scope to a list if it's a string
        if isinstance(scope, str):
            scope = [scope]

        # Here we compile the fields for the new Signing table row
        SIGNING_FIELDS = {  'signature':key, 
                    'scope':[s.lower() for s in scope] if scope else [],
                    'email':email.lower() if email else "", 
                    'active':active,
                    'rotated': False,
                    'expiration':(datetime.datetime.utcnow() + datetime.timedelta(hours=expiration)) if expiration else 0,
                    'timestamp':datetime.datetime.utcnow(),
        }

        # If we've passed a parent key, then we modify the new row with the parent ID
        # Note: this defaults to NULL if not passed.
        if previous_key:
            SIGNING_FIELDS['previous_key'] = previous_key

        new_key = Signing(**SIGNING_FIELDS)

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
    

    @request_limiter
    def verify_key(self, signature, scope):
        """
        Validates a request by verifying the given signing key against a specific scope.
        
        This function wraps the `check_key` function and adds rate limiting support. 
        If rate limiting is enabled, it checks whether the request count for the signature 
        has exceeded the maximum allowed requests within the specified time period.
        
        If the rate limit is exceeded, it raises a `RateLimitExceeded` exception and returns False.
        If the rate limit is not exceeded, or is not enabled, this calls the `check_key` function 
        to verify the key.
        
        Args:
            signature (str): The signing key to be verified.
            scope (str): The scope against which the signing key will be validated.

        Returns:
            bool: True if the signing key is valid and hasn't exceeded rate limit, False otherwise.

        Raises:
            RateLimitExceeded: If the number of requests with this signing key exceeds 
            the maximum allowed within the specified time period.
        """

        try:
            valid = self.check_key(signature, scope)
        except RateLimitExceeded as e:
            print(e)  # Or handle the exception in some other way
            return False

        return valid

    def check_key(self, signature, scope):
        """
        Checks the validity of a given signing key against a specific scope.

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

        # Convert scope to a list if it's a string
        if isinstance(scope, str):
            scope = [scope]

        # if the signing key's scope doesn't match any of the required scopes
        if not set(scope).intersection(set(signing_key.scope)):
            return False

        # # if the signing key's scope doesn't match the required scope
        # if signing_key.scope != scope:
        #     return False

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
                # scope = self.db.Column(self.db.String(100))
                # scope = self.db.Column(self.db.MutableList.as_mutable(self.db.String(100)), default=[]),
                scope = self.db.Column(self.db.JSON())
                active = self.db.Column(self.db.Boolean)
                timestamp = self.db.Column(self.db.DateTime, nullable=False, default=datetime.datetime.utcnow)
                expiration = self.db.Column(self.db.DateTime, nullable=False, default=datetime.datetime.utcnow)
                request_count = self.db.Column(self.db.Integer, default=0)
                last_request_time = self.db.Column(self.db.DateTime, default=datetime.datetime.utcnow)
                # previous_key = self.db.Column(self.db.String(1000), db.ForeignKey('signing.signature'))
                previous_key = self.db.Column(self.db.String(1000), self.db.ForeignKey('signing.signature'), nullable=True)
                rotated = self.db.Column(self.db.Boolean)
                # parent = db.relationship("Signing", remote_side=[signature]) # self referential relationship
                children = self.db.relationship('Signing', backref=self.db.backref('parent', remote_side=[signature])) # self referential relationship

            self._model = Signing

        return self._model


    def query_keys(self, active:bool=None, scope:str=None, email:str=None, previous_key:str=None) -> Union[List[Dict[str, Any]], bool]:
        """
        Query signing keys by active status, scope, email, and previous_key.

        This function returns a list of signing keys that match the provided parameters.
        If no keys are found, it returns False.

        Args:
            active (bool, optional): The active status of the signing keys. Defaults to None.
            scope (str, optional): The scope of the signing keys. Defaults to None.
            email (str, optional): The email associated with the signing keys. Defaults to None.
            previous_key (str, optional): The previous_key associated with the signing keys. Defaults to None.

        Returns:
            Union[List[Dict[str, Any]], bool]: A list of dictionaries where each dictionary contains the details of a signing key,
            or False if no keys are found.
        """

        Signing = self.get_model()

        query = Signing.query

        if active is not None:
            query = query.filter(Signing.active == active)

        # Convert scope to a list if it's a string
        if isinstance(scope, str):
            scope = [scope]

        if scope:

            for s in scope:
                # https://stackoverflow.com/a/44250678/13301284
                query = query.filter(Signing.scope.comparator.contains(s))

                # https://stackoverflow.com/a/39470478/13301284
                # query = query.filter(func.json_contains(Signing.scope, s) == 1)
                # query = query.filter(literal(s).bool_op('MEMBER OF')(Signing.scope.self_group()))
                
            # query = query.filter(Signing.scope.in_(scope))
            
        # if scope:
        #     query = query.filter(Signing.scope == scope)

        if email:
            query = query.filter(Signing.email == email)

        if previous_key:
            query = query.filter(Signing.previous_key == previous_key)

        result = query.all()

        if not result:
            return False

        return [{'signature': key.signature, 'email': key.email, 'scope': key.scope, 'active': key.active, 'timestamp': key.timestamp, 'expiration': key.expiration, 'previous_key': key.previous_key, 'rotated': key.rotated} for key in result]

    def get_all(self) -> List[Dict[str, Any]]:

        """
        Query all values in the Signing table.
        If no keys are found, it returns an empty list.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries where each dictionary contains the details of a signing key.

        """
        return [{'signature': key.signature, 'email': key.email, 'scope': key.scope, 'active': key.active, 'timestamp': key.timestamp, 'expiration': key.expiration, 'previous_key': key.previous_key, 'rotated': key.rotated} for key in self.get_model().query.all()]


    def rotate_keys(self, time_until:int=1, scope=None) -> bool:
        """
        Rotates all keys that are about to expire.
        This is written with the background processes in mind. This can be wrapped in a celerybeat schedule or celery task.
        Args:
            time_until (int): rotate keys that are set to expire in this many hours.
            scope (str, list): rotate keys within this scope. If None, all scopes are considered.
        Returns:
            bool: operation succeeded/failed.
        """
        try:
            Signing = self.get_model()

            # get keys that will expire in the next time_until hours
            query = Signing.query.filter(
                Signing.expiration <= (datetime.datetime.utcnow() + datetime.timedelta(hours=time_until)),
                Signing.active == True
            )

            # if scope is not None:
            #     if isinstance(scope, list):
            #         query = query.filter(Signing.scope.in_(scope))
            #     else:
            #         query = query.filter_by(scope=scope)

            # Convert scope to a list if it's a string
            if isinstance(scope, str):
                scope = [scope]

            if scope:

                for s in scope:
                    # https://stackoverflow.com/a/44250678/13301284
                    query = query.filter(Signing.scope.comparator.contains(s))

            expiring_keys = query.all()

            for key in expiring_keys:
                self.rotate_key(key.signature)

        except SQLAlchemyError as e:
            # This will catch any SQLAlchemy related exceptions
            print(f"An error occurred while rotating keys: {e}")
            return False

        except Exception as e:
            # This will catch any other kind of unexpected exceptions
            print(f"An unexpected error occurred: {e}")
            return False

        # We may need to potentially modify the return behavior to provide greater detail ... 
        # for example, a list of old keys mapped to their new keys and emails.
        return True

    def rotate_key(self, key: str, expiration:int=1) -> str:
        """
        Replaces an active key with a new key with the same properties, and sets the old key as inactive.
        Args:
            key (str): The signing key to be rotated.
            expiration (int): The number of hours until the new key will expire.
        Returns:
            str: The new signing key.
        """
        try:
            Signing = self.get_model()

            signing_key = Signing.query.filter_by(signature=key).first()

            if not signing_key:
                raise ValueError("No such key exists")

            if self.safe_mode and signing_key.rotated:
                raise ValueError("Key has already been rotated")

            if self.safe_mode and not signing_key.active:
                raise ValueError("You cannot rotate a disabled key")

            # Disable old key
            signing_key.active = False
            signing_key.rotated = True
            self.db.session.flush()

            # Generate a new key with the same properties
            new_key = self.write_key(
                scope=signing_key.scope, 
                expiration=expiration, 
                active=True, 
                email=signing_key.email,
                previous_key=signing_key.signature,  # Assign old key's signature to the previous_key field of new key
            )
            
            self.db.session.commit()

        except SQLAlchemyError as e:
            # print(f"An error occurred while rotating the key {key}: {e}")
            return False

        except Exception as e:
            # print(f"An unexpected error occurred: {e}")
            return False

        return new_key