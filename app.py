#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

import jwt
from flask_restplus import Api, Resource, fields, Namespace
from flask_cors import CORS
from flask_migrate import Migrate
import datetime

##########
# Config #
##########

PRIVATE_KEY = os.environ['PRIVATE_KEY']
PUBLIC_KEY = os.environ['PUBLIC_KEY']
URL = os.environ['URL']

ROLE_KEYS = {
        os.environ['ADMIN_KEY']: 'admin',
        os.environ['USER_KEY']: 'user',
        }
########
# Init #
########

# initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = URL
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# extensions
CORS(app)
db = SQLAlchemy(app)
auth = HTTPBasicAuth()
api = Api(app, version='1.2', title='Authenticator',
            description='FreeGenes authenticator',
            )
migrate = Migrate(app, db)

#
# Models
#

users_roles = db.Table('users_roles',
    db.Column('users_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('roles_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True, nullable=True),
)
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, index=True)
    password_hash = db.Column(db.String(150))
    roles = db.relationship('Role', secondary=users_roles, lazy='subquery',
        backref=db.backref('users', lazy=True))

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        encoded = jwt.encode({**{'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration),'iat': datetime.datetime.utcnow()}, **self.toJSON()}, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
        return encoded

    def toJSON(self):
        return {'username':self.username,'roles': [role.role for role in self.roles]}

    @staticmethod
    def verify_auth_token(token):
        try:
            decoded = jwt.decode(token.encode("utf-8"), PUBLIC_KEY, algorithms='RS256')
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        except Exception as e:
            return None # something else funky happened
        user = User.query.get(decoded['id'])
        return user

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


##############
# Namespaces #
##############

ns_keys = Namespace('public_key', description='Public key')
@ns_keys.route('/')
class PublicKey(Resource):
    def get(self):
        return jsonify({'public_key': PUBLIC_KEY})

ns_users = Namespace('users', description='User login')
user_model = ns_users.model("user", {
    "username": fields.String(),
    "password": fields.String(),
    "role_keys": fields.List(fields.String())
    })
role_model = ns_users.model("roles", {
    "role_keys": fields.List(fields.String())
    })

def apply_roles(user,role_keys):
    roles = [ROLE_KEYS[key] for key in role_keys if key in ROLE_KEYS] # Find new roles
    if len(roles) == 0:
        abort(403)
    preexisting_roles = user.toJSON()['roles']
    roles = [role for role in roles if role not in preexisting_roles] # Not already there
    db_roles = []
    for role in roles: # Find in db
        roles_in_db = Role.query.filter_by(role=role).all()
        if len(roles_in_db) == 0:
            user.roles.append(Role(role=role))
        else:
            user.roles.append(roles_in_db[0])
    return user

@ns_users.route('/')
class UserPostRoute(Resource):
    @ns_users.doc('user_create')
    @ns_users.expect(user_model)
    def post(self):
        '''Post new user. Checks for Login key'''
        username = request.json.get('username')
        password = request.json.get('password')
        role_keys = request.json.get('role_keys')
        if username is None or password is None:
            abort(400)    # missing arguments
        if User.query.filter_by(username=username).first() is not None:
            abort(400)    # existing user
        user = User(username=username)
        user.hash_password(password)
        
        user = apply_roles(user,role_keys)
        db.session.add(user)
        db.session.commit()
        return jsonify(user.toJSON())

@ns_users.route('/new_role/<username>')
class NewRole(Resource):
    @ns_users.doc('user_new_role')
    @ns_users.expect(role_model)
    @auth.login_required
    def put(self,username):
        user = User.query.filter_by(username=username).first()
        role_keys = request.json.get('role_keys')
        user = apply_roles(user,role_keys)
        db.session.add(user)
        db.session.commit()
        return jsonify(user.toJSON())

@ns_users.route('/token')
class TokenRoute(Resource):
    @ns_users.doc('user_token')
    @auth.login_required
    def get(self):
        token = g.user.generate_auth_token(600)
        return jsonify({'token': token, 'duration': 600})

@ns_users.route('/admin/token/<expiration>')
class AdminTokenRoute(Resource):
    @ns_users.doc('admin_token')
    @auth.login_required
    def get(self,expiration):
        expiration = int(expiration)
        if expiration > 86400:
            return {'message': 'Expiration too long'}
        token = g.user.generate_auth_token(expiration)
        return jsonify({'token': token, 'duration': expiration})


@ns_users.route('/resource')
class ResourceRoute(Resource):
    @ns_users.doc('user_resource')
    @auth.login_required
    def get(self):
        return jsonify({'data': 'Success {}'.format(g.user.username)})


api.add_namespace(ns_users)
api.add_namespace(ns_keys)

if __name__ == '__main__':
    app.run()
