""" 
signing.py: function set for managing signing keys and corresponding database operations

Signing keys, or signatures (we use these terms interchangeably), are used 
in various situations to authenticate a user when requiring users to login 
- or even register an account - is not a reasonable expectation, but where we 
would still like to be able to strongly authenticate a user before a privileged 
behavior is permitted by the application. This script defines a set of 
operations to generate and manage these signatures using the signing database 
defined in app/models.py, which is a useful script to review for more 
information on the data model. 

# Scope

One point from the data model that will be useful to discuss here is the signature's 
`scope`, which is a field that describes the purpose of a given signature. We employ 
a mixed approach when using a `scope` to constrain a signature's use. For 
example, a signature's scope will not, in itself, be used to set the signature's 
expiration behavior - that is set when write_key_to_database() is invoked and
is defined alongside the signature's scope, see below for more information.
What this means in practice is that the end user retains the freedom to 
set the expiration behavior of different scopes or subsets of scopes. 

However, to prevent improper use of signatures, scopes may not be used for
interchangeable purposes, such that a signature with a scope of 'forgot_password'
cannot be used in an application function requiring a scope of 'email_verification'.
This is a common sense rule that is enforced through some boilerplate that should
be run everytime a signature is invoked. Take, for example, the following code from
app/auth.py, which verifies that a signature exists, that it is active and unexpired,
and that it contains the appropriate scope. Feel free to repurpose the code below for
additional views that may require signature validation. 

```
    if not Signing.query.filter_by(signature=signature).first():
        flash(flash_msg)
        return redirect(url_for(redirect_to))

    # if the signing key's expiration time has passed, then set it to inactive 
    if Signing.query.filter_by(signature=signature).first().expiration < datetime.datetime.timestamp(datetime.datetime.now()):
        signing.expire_key(signature)

    # if the signing key is set to inactive, then we prevent the user from proceeding
    # this might be redundant to the above condition - but is a good redundancy for now
    if Signing.query.filter_by(signature=signature).first().active == 0:
        flash(flash_msg)
        return redirect(url_for(redirect_to))

    # if the signing key is not scoped (that is, intended) for this purpose, then 
    # return an invalid error
    if not Signing.query.filter_by(signature=signature).first().scope == "forgot_password":
        flash(flash_msg)
        return redirect(url_for(redirect_to))
```

Notably, we added verify_signatures(), see below, to an abstract method to apply the logic above 
in a view.

Some scopes that this application implements - primarily located in app/auth.py,
app/api.py, and app/external.py are:

1.  api_key: the base application sets the expiration date at 365 days, and does not expire
    the key after a given use by default, though it does allow administrators to limit the 
    number of API keys a single user / email may register. 

    In the future, there may be some value in setting a dynamic scope for API keys, as in (4)
    below, to permit different sets of CRUD operations.

2.  forgot_password: the base application sets the expiration date at 1 hour, and expires the
    key after a single use.

3.  email_verification: the base application sets the expiration date at 48 hours, and expires 
    the key after a single use.

4.  external_{form_name.lower()}: the base application assesses external / anonymous form 
    submissions dynamically depending on the form name; it sets the expiration date at 48 
    hours and expires the key after a single use.


# generate_key(length=24) 

Generates and returns a signature string defaulting to 24 characters in length.

In the base application, this method is called almost exclusively by write_key_to_database(), 
see below. It made sense to externalize it, however, because there are a reasonable and abstract
set of uses for this function outside the context of the application's signing database and
corresponding data model. It takes a single parameter `length`, which is an integer corresponding
to the length of the signature that the function generates and returns. 


# write_key_to_database(scope=None, expiration=1, active=1, email=None)

Connector function that generates a signature entry conforming to the signing data model.

For more explanation of `scope`, see the corresponding section above. The `expiration` should
be set in hours relative to the current timestamp. Setting signatures to `active` by default
when no futher action is needed to enable them. Setting `email` to None by default may be a
bug or feature, depending on context. Either way, future code revisions may choose to modify 
this behavior to require an email to be set - but then it may break instances where emails are 
not required, or where the 'libreforms' user continues to not have an email set. 


# flush_key_db()

Disables any signatures in the signing database whose expiration timestamp has passed.

In the base application, this method remains largely unimplemented in favor of 
expire_key(), see below. That is because there is no plausible trigger for it -
even though it is theoretically / potentially more efficient than expire_key(),
especially when it catches & expires multiple signatures whose expirations have
passed. 

Implementation probably makes more sense if we can run it asynchronously and
thus trigger on a schedule instead of by an event. For example, maybe we query 
the signing database every hour (since this is the lowest possible increment 
expiration increment), select the row with the lower value for `expiration` 
where active == 1 (so we're selecting the next key set to expire). Then,
we create a single croniter schedule, as in app/reports.py and pass this 
to a timed asynchronous function. Or maybe we just string this without 
running hourly checks - that might be overkill. This allows some degree of
precision in expiring keys.


# expire_key(key=None)

Expire a specific key without any logic or verification.

In the base application, this method is used to expire a specific key. It is 
primarily used when each signature is invoked in the client; take, this example 
from the `scope` section above:

    # if the signing key's expiration time has passed, then set it to inactive 
    if Signing.query.filter_by(signature=signature).first().expiration < datetime.datetime.timestamp(datetime.datetime.now()):
        signing.expire_key(signature)

Make note, all logic determining whether the key should be expired is external to 
this method; it only takes a key as a parameter and expires it.

# def verify_signatures(signature, # the key to validate
                            scope, # what scope the signature should be validated against
                            redirect_to='home', # failed validations redirect here unless abort_on_errors=True
                            flash_msg="Invalid request key. ", # failed validations give msg unless abort_on_errors=True
                            abort_on_error=False, # if True, failed validations will return a 404):

Verify an individual signature and return None if it passes.

In the base application, this function requires two parameters: a `signature` string and a 
`scope` to validate against the database. It has optional parameters to set where to `redirect_to`
on errors, what `flash_msg` to show the user when a key validation fails, and a bool option to 
have the view return a 404 error when key validation fails.

This functiom applies the logic discussed in the `Scope` section above. You would include in a view in
one of two ways: first, as a conditional:

```
if not signing.verify_signatures(signature, scope="forgot_password"):
    return YOUR VIEW HERE
else:
    return abort(404)
```

Alternatively, if you set the `abort_on_error` option to True, then you can simply call it in your view
without needing to deal with nesting conditionals:

```
signing.verify_signatures(signature, scope="forgot_password", abort_on_error=True)
return YOUR VIEW HERE
```

"""


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

        if not Signing.query.filter_by(signature=signature).first():
            return False

        # if the signing key's expiration time has passed, then set it to inactive 
        if Signing.query.filter_by(signature=signature).first().expiration < datetime.datetime.now():
            self.expire_key(signature)

        # if the signing key is set to inactive, then we prevent the user from proceeding
        # this might be redundant to the above condition - but is a good redundancy for now
        if Signing.query.filter_by(signature=signature).first().active == 0:
            return False

        # if the signing key is not scoped (that is, intended) for this purpose, then 
        # return an invalid error
        if not Signing.query.filter_by(signature=signature).first().scope == scope:
            return False

        # Returning True is desirable. It means that we can run `if verify_signatures():` 
        # as a way to require the check passes...
        return True

