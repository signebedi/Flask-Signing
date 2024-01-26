from .__metadata__ import (__name__, __author__, __credits__, __version__, 
                       __license__, __maintainer__, __email__)
import datetime, secrets
from functools import wraps
from sqlalchemy import func, literal
from sqlalchemy.exc import SQLAlchemyError
from flask_sqlalchemy import SQLAlchemy
from typing import Union, List, Dict, Any, Optional
from itsdangerous import URLSafeTimedSerializer


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

class KeyDoesNotExist(Exception):
    """
    An exception that is raised when a requested signing key does not exist in the 
    system. This could happen if the key has been deleted, never created, or if there 
    is a mismatch in the key identifier used for lookup.

    This exception indicates that the operation cannot proceed without a valid signing 
    key, and the calling code should catch this exception to handle these cases 
    appropriately.
    """
    pass

class KeyExpired(Exception):
    """
    An exception that is raised when the signing key's expiration time has passed
    or the key is marked inactive. Expired keys are considered invalid for crypto
    graphic operations.

    This exception helps in enforcing security protocols where only active keys should 
    be used, allowing the calling code to handle such situations accordingly, such as 
    notifying the user or selecting an alternate key.
    """
    pass

class ScopeMismatch(Exception):
    """
    An exception that is raised when the scope associated with the signing key does not 
    match any of the required scopes specified in the operation.

    This exception is crucial for maintaining scope-based access control, ensuring that 
    operations are performed only with keys that have the appropriate scope. The calling 
    code should handle this exception to enforce correct scope usage.
    """
    pass

class AlreadyRotated(Exception):
    """
    An exception that is raised when there is an attempt to rotate an already-rotated
    key.

    This exception will help prevent keys that have gone stale from being rotated and 
    producing further children keys.
    """
    pass


class Signatures:
    """
    The Signatures class handles operations related to the creation, management, and validation 
    of signing keys in the database.
    """
    
    def __init__(self, app, db=None, safe_mode:bool=True, byte_len:int=24, rate_limiting=False, rate_limiting_max_requests=10, rate_limiting_period=datetime.timedelta(minutes=1)):
        """
        Initializes a new instance of the Signatures class.

        Args:
            app (Flask): A flask object to contain the context for database interactions. 
            db (SQLAlchemy, optional): An optional SQLAlchemy db object to inherit an app's existing data model. Defaults to False.
            safe_mode (bool, optional): If safe_mode is enabled, we will prevent rotation of disabled or rotated keys. Defaults to True.
            byte_len (int, optional): The length of the generated signing keys. Defaults to 24.
            rate_limiting (bool, optional): If rate_limiting is enabled, we will impose key-by-key rate limits. Defaults to False.
            rate_limiting_max_requests (int, optional): Maximum allowed requests per time period.
            rate_limiting_period (datetime.timedelta, optional): Time period for rate limiting. Defaults to 1 hour.
        """
        if db is not None:
            self.db = db
            self.Signing = self.get_model()
        else:
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
                if signing_key:

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

    def write_key(self, scope:str=None, expiration:int=0, active:bool=True, email:str=None, previous_key:str=None) -> str:
        """
        Writes a newly generated signing key to the database.

        This function will continuously attempt to generate a key until a unique one is created. 

        Args:
            scope (str): The scope within which the signing key will be valid. Defaults to None.
            expiration (int, optional): The number of hours after which the signing key will expire. 
                If not provided or equals 0, the expiration will be set to zero (no-expiry). Defaults to 0.
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
                    # If nothing is passed, set an absurdly-high expiry datetime
                    'expiration':(datetime.datetime.utcnow() + datetime.timedelta(hours=expiration)) if expiration else datetime.datetime(9999, 12, 31, 23, 59, 59),
                    'expiration_int':expiration,
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
            raise KeyDoesNotExist("This key does not exist.")

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

        # try:
        #     valid = self.check_key(signature, scope)
        # except RateLimitExceeded as e:
        #     print(e)  # Or handle the exception in some other way
        #     return False
        # return valid

        return self.check_key(signature, scope)

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
            # return False
            raise KeyDoesNotExist("This key does not exist.")

        # if the signing key is set to inactive
        if not signing_key.active:
            # return False
            raise KeyExpired("This key is no longer active.")

        # if the signing key's expiration time has passed
        if signing_key.expiration < datetime.datetime.utcnow():
            self.expire_key(signature)
            # return False
            raise KeyExpired("This key is expired.")

        # Convert scope to a list if it's a string
        if isinstance(scope, str):
            scope = [scope]

        # if the signing key's scope doesn't match any of the required scopes
        if not set(scope).intersection(set(signing_key.scope)):
            raise ScopeMismatch("This key does not match the required scope.")

        # # if the signing key's scope doesn't match the required scope
        # if signing_key.scope != scope:
        #     return False

        return True

    def get_model(self):

        """
        Return a single instance of the Signing class, which represents the Signing table in the database.

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
                # A 0 expiration int means it will never expire
                expiration_int = self.db.Column(self.db.Integer, nullable=False, default=0)
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
                
        if email:
            query = query.filter(Signing.email == email)

        if previous_key:
            query = query.filter(Signing.previous_key == previous_key)

        result = query.all()

        if not result:
            raise Exception("No results found for given parameters.")

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
            List[Tuple[str, str]]: A list of tuples containing old keys and the new keys replacing them
        """
        Signing = self.get_model()

        # get keys that will expire in the next time_until hours
        query = Signing.query.filter(
            Signing.expiration <= (datetime.datetime.utcnow() + datetime.timedelta(hours=time_until)),
            Signing.active == True
        )

        # Convert scope to a list if it's a string
        if isinstance(scope, str):
            scope = [scope]

        if scope:

            for s in scope:
                # https://stackoverflow.com/a/44250678/13301284
                query = query.filter(Signing.scope.comparator.contains(s))

        expiring_keys = query.all()

        key_list = []

        for key in expiring_keys:

            old_key = key.signature
            new_key = self.rotate_key(key.signature)

            key_list.append((old_key, new_key))

        # We may need to potentially modify the return behavior to provide greater detail ... 
        # for example, a list of old keys mapped to their new keys and emails.
        # return True
        return key_list

    def rotate_key(self, key: str, expiration:Optional[int]=None) -> str:
        """
        Replaces an active key with a new key with the same properties, and sets the old key as inactive.
        Args:
            key (str): The signing key to be rotated.
            expiration (int): The number of hours until the new key will expire.
        Returns:
            str: The new signing key.
        """

        Signing = self.get_model()

        signing_key = Signing.query.filter_by(signature=key).first()

        if not signing_key:
            raise KeyDoesNotExist("This key does not exist.")

        if self.safe_mode and signing_key.rotated:
            raise AlreadyRotated("Key has already been rotated")

        if self.safe_mode and not signing_key.active:
            raise KeyExpired("You cannot rotate a disabled key")

        # Disable old key
        signing_key.active = False
        signing_key.rotated = True
        self.db.session.flush()


        # If no expiration int is passed, we inherit the parent's
        if expiration is None:
            expiration = signing_key.expiration_int

        # Generate a new key with the same properties
        new_key = self.write_key(
            scope=signing_key.scope,
            expiration=expiration,
            active=True, 
            email=signing_key.email,
            previous_key=signing_key.signature,  # Assign old key's signature to the previous_key field of new key
        )
        
        self.db.session.commit()

        return new_key


class DangerousSignatures(Signatures):

    """
    The DangerousSignatures class handles operations related to the creation, management, 
    and validation of signing keys in the database using the itsdangerous library.
    """
    
    def __init__(self, app, secret_key:str=None, salt:str=None, *args, **kwargs):
        """
        Initializes a new instance of the DangerousSignatures class.

        Args:
            app (Flask): A flask object to contain the context for database interactions. 
            secret_key (str, optional): Value to use as a secret key. Defaults to the app.secret_key.
            salt (str, optional): Value to use as the salt. Defaults to flask-signing.

        """
        self.app = app
        super().__init__(self.app, *args, **kwargs)
        
        self.secret_key = secret_key or self.app.secret_key
        self.salt = salt or 'flask-signing'
        self.serializer = URLSafeTimedSerializer(self.secret_key)


    def generate_key(self, additional_data: dict = None, length:int=None) -> str:
        """
        Overrides the parent generate_key method to use itsdangerous for key generation.

        Args:
            additional_data (dict, optional): Additional data to be included in the token. Defaults to None.
            length (int, optional): The length of the generated signing key. Defaults to None, in which case the byte_len is used.

        Returns:
            str: The generated signing key.
        """
        if not length: 
            length = self.byte_len

        data = {"key": secrets.token_urlsafe(length)}

        # If additional_data is provided, update the data dictionary
        if additional_data is not None:
            data.update(additional_data)

        return self.serializer.dumps(data)
