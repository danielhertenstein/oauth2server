from datetime import datetime, timedelta
from enum import Enum
from flask import Flask
from flask import abort, jsonify, redirect, request
from flask_sqlalchemy import SQLAlchemy
from secrets import token_urlsafe


app = Flask(__name__)
app.secret_key = 'secret'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)


class token_type(Enum):
    AUTH_CODE = 0
    ACCESS_TOKEN = 1
    REFRESH_TOKEN = 2


ACCESS_TOKEN_EXPIRATION = 3600  # seconds
AUTHORIZATION_EXPIRATION = 600  # seconds


class Token(db.Model):
    code = db.Column(db.String(255), primary_key=True)
    client_id = db.Column(db.String(40))
    expires = db.Column(db.DateTime)
    token_type = db.Column(db.Integer)
    # TODO: Add user_id


def verify_client_id(client_id):
    if client_id != 'Google client ID':
        # TODO: What do I do if it doesn't match?
        pass


@app.route('/auth', methods=['GET', ])
def authenticate():
    if request.method == 'GET':
        client_id = request.args.get('client_id', '')
        redirect_uri = request.args.get('redirect_uri', '')
        state = request.args.get('state', '')
        scope = request.args.get('scope', '')
        response_type = request.args.get('response_type', '')

        # Verify client_id matches the registered Google client ID
        verify_client_id(client_id)

        # Verify redirect_uri matches the Google provided redirect URL for the service
        if redirect_uri != 'https://oauth-redirect.googleusercontent.com/r/YOUR_PROJECT_ID':
            # TODO: What do I do if it doesn't match?
            pass

        # Confirm response_type is 'code'
        if response_type != 'code':
            # TODO: What do I do if it doesn't match?
            pass

        # Prompt user to access any scopes defined in the scopes parameter

        # Generate an authentication code for Google to access the API
        expires = datetime.utcnow() + timedelta(seconds=AUTHORIZATION_EXPIRATION)
        authorization_code = token_urlsafe(32)
        token = Token(
            code=authorization_code,
            client_id=client_id,
            expires=expires,
            token_type=token_type.AUTH_CODE,
        )
        db.session.add(token)
        db.session.commit()

        # Redirect the user
        redirect_url = '{0}?code={1}&state={2}'.format(redirect_uri, authorization_code, state)
        return redirect(redirect_url)

    return "Authentication page"


@app.route('/token', methods=['POST', ])
def token():
    if request.method == 'POST':
        client_id = request.args.get('client_id', '')
        client_secret = request.args.get('client_secret', '')
        grant_type = request.args.get('grant_type', '')

        # Verify client_id matches the registered Google client ID
        verify_client_id(client_id)

        # Verify client secret
        if client_secret != 'expected_value':  # TODO: What is the expected value?
            pass

        # Handle authorization code case
        if grant_type == 'authorization_code':
            # Verify the authorization code
            code = request.args.get('code', '')
            token = Token.query.filter_by(code=code).first()
            if token is None:
                return invalid_grant_error()
            if token.client_id != client_id:
                return invalid_grant_error()
            if datetime.utcnow() > token.expires:
                return invalid_grant_error()

            # Make refresh token
            refresh_code = token_urlsafe(32)
            token = Token(
                code=refresh_code,
                client_id=client_id,
                token_type=token_type.REFRESH_TOKEN,
            )
            db.session.add(token)
            db.session.commit()

            # Make access token
            access_code = token_urlsafe(32)
            expires = datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_EXPIRATION)
            token = Token(
                code=access_code,
                client_id=client_id,
                expires=expires,
                token_type=token_type.ACCESS_TOKEN,
            )
            db.session.add(token)
            db.session.commit()

            body = jsonify(
                token_type = "bearer",
                access_token = access_code,
                refresh_token = refresh_code,
                expires_in = ACCESS_TOKEN_EXPIRATION,
            )
            return body

        # Handle refresh token case
        elif grant_type == 'refresh_token':
            # Verify the refresh token
            refresh_token = request.args.get('refresh_token', '')
            token = Token.query.filter_by(code=refresh_token).first()
            if token is None:
                return invalid_grant_error()
            # Verify the user still has authorization

            # Make access token
            access_code = token_urlsafe(32)
            expires = datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_EXPIRATION)
            token = Token(
                code=access_code,
                client_id=client_id,
                expires=expires,
                token_type=token_type.ACCESS_TOKEN,
            )
            db.session.add(token)
            db.session.commit()

            body = jsonify(
                token_type = "bearer",
                access_token = access_code,
                expires_in = ACCESS_TOKEN_EXPIRATION,
            )
            return body

        else:  # TODO: Do I need to worry about this case?
            pass

    return "Token page"


@app.route('/service', methods=['GET, '])
def service():
    if request.method == 'GET':
        # TODO: It doesn't seem like this is the right way to get the token
        access_token = request.args.get('access_token', '')
        token = Token.query.filter_by(code=access_token).first()
        if token is None:
            return abort(401)
        if token.token_type != token_type.ACCESS_TOKEN:
            return abort(401)
        if datetime.utcnow() > token.expires:
            return abort(401)
        # TODO: Verify scopes grant access to endpoint
        # TODO: Respond to the request

    return "Service page"



def invalid_grant_error():
    response = jsonify(
        error = "invalid_grant"
    )
    response.status_code = 400
    return response


if __name__ == '__main__':
    db.create_all()
    app.run()
