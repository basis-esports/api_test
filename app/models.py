from app import app, db, bcrypt
from app.facebook import facebook
from sqlalchemy import desc, exc, orm, Index, func, select

from flask import Blueprint, jsonify, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields
from trueskill import Rating, rate_1vs1

import datetime
import jwt
import random


followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

friendships = db.Table('friendships',
    db.Column('friender_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('friended_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

friend_requests = db.Table('friend_requests',
    db.Column('friender_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('friended_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

taggings = db.Table('taggings',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('tag_name', db.String, db.ForeignKey('tags.name'), nullable=False),
)

blocks = db.Table('blocks',
    db.Column('blocker_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('blocked_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    registered_on = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=True)

    # User information
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    gender = db.Column(db.Enum("male", "female"), nullable=False)
    age = db.Column(db.Integer)
    password = db.Column(db.String(255), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    game = db.Column(db.String(64), nullable=False)

    score = db.Column(db.Float, default=25.0, server_default="25.0")
    sigma = db.Column(db.Float, default=8.333, server_default="8.333")

    # Riot Games integration
    # maybe make nullable=False?
    summoner_id = db.Column(db.String(100), nullable=True)

    # Facebook integration
    # facebook_id is None if no account has been connected
    facebook_id = db.Column(db.String(100), nullable=True)
    facebook_name = db.Column(db.String(50), nullable=True)

    # Things related to location
    # Change to current_location_id
    current_location_id = db.Column(db.Integer, db.ForeignKey('locations.id'))

    # Relationships
    location = db.relationship(
        'User', secondary=lcoations,
        primaryjoin=(locations.c.location_id == id),
        backref=db.backref('locations', lazy='dynamic'), lazy='dynamic')
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    friended = db.relationship(
        'User', secondary=friendships,
        primaryjoin=(friendships.c.friender_id == id),
        secondaryjoin=(friendships.c.friended_id == id),
        backref=db.backref('frienders', lazy='dynamic'), lazy='dynamic')
    friend_requests_sent = db.relationship(
        'User', secondary=friend_requests,
        primaryjoin=(friend_requests.c.friender_id == id),
        secondaryjoin=(friend_requests.c.friended_id == id),
        backref=db.backref('friend_requests_received', lazy='dynamic'), lazy='dynamic')
    blocked = db.relationship(
        'User', secondary=blocks,
        primaryjoin=(blocks.c.blocker_id == id),
        secondaryjoin=(blocks.c.blocked_id == id),
        backref=db.backref('blocked_by', lazy='dynamic'), lazy='dynamic')
    updates = db.relationship('Update', backref='user', lazy=True)

    # Location
    location = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    address = db.Column(db.String(256), nullable=True)

    def __init__(self, name, email, gender, password, game, confirmed=False, age=None):
        self.name = name
        self.email = email
        self.gender = gender
        self.set_password(password)
        self.game = game # <- new addition
        self.city_id = city_id
        self.confirmed = confirmed
        self.age = age
        self.registered_on = datetime.datetime.utcnow()

    @property
    def sweaty(self):
        minmax = db.engine.execute("SELECT MIN(score), MAX(score) FROM User")

        low, high = minmax.fetchone()
        if low == high:
            return 10

        return (self.score - low) / (high - low) * 10

    def generate_token(self):
        """
        Generate auth token.
        :return: token and expiration timestamp.
        """
        now = datetime.datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + datetime.timedelta(days=3650),
            'sub': self.id,
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        ).decode(), payload['exp']

    @staticmethod
    def from_token(token):
        """
        Decode/validate an auth token.
        :param token: token to decode.
        :return: User whose token this is, or None if token invalid/no user associated
        """
        try:
            payload = jwt.decode(token, app.config.get('SECRET_KEY'))
            is_blacklisted = BlacklistedToken.check_blacklist(token)
            if is_blacklisted:
                # Token was blacklisted following logout
                return None
            return User.query.get(payload['sub'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            # Signature expired, or token otherwise invalid
            return None

    def is_password_correct(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password, password)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()

    def search(self, query: str):
        users = User.query.filter(User.id != self.id,
                                  User.name.ilike('%' + query + '%'),
                                  User.confirmed == True,
                                  User.game == self.game)
        return users.limit(10).all()

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)
            return True
        return False

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
            return True
        return False

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def block(self, user):
        if not self.is_blocking(user):
            self.blocked.append(user)
            return True
        return False

    def unblock(self, user):
        if self.is_blocking(user):
            self.blocked.remove(user)
            return True
        return False

    def is_blocking(self, user):
        return self.blocked.filter(blocks.c.blocked_id == user.id).count() > 0

    def friends(self):
        """
        Get a list of people you have friended and who have friended you whose friendships are confirmed.
        """
        return self.friended.union(self.frienders).all()

    def is_friends_with(self, user) -> bool:
        return self.friended.filter(friendships.c.friended_id == user.id).count() > 0 \
            or self.frienders.filter(friendships.c.friender_id == user.id).count() > 0

    def friend_requests(self):
        """
        Get a list of users who have sent friend requests to you that are not confirmed yet.
        """
        return self.friend_requests_received.all()

    def friend_request(self, user):
        if self.has_friend_request(user) or self.is_friends_with(user):
            return False
        self.friend_requests_sent.append(user)
        return True

    def has_received_friend_request(self, user) -> bool:
        """
        Have I received a friend request from the given user?
        """
        return self.friend_requests_received.filter(friend_requests.c.friender_id == user.id).count() > 0

    def has_sent_friend_request(self, user) -> bool:
        """
        Have I sent a friend request from the given user?
        """
        return self.friend_requests_sent.filter(friend_requests.c.friended_id == user.id).count() > 0

    def has_friend_request(self, user) -> bool:
        """
        Return whether there is an active friend request (received or sent) to the given user.
        """
        return self.has_received_friend_request(user) or self.has_sent_friend_request(user)

    #def feed(self):
        #['TBD'] = self.['TBD'].filter_by()
        #['TBD'] = ['TBD'].union()
        #['TBD'] = ['TBD'].query.filter_by()

        # Put specifc things first
        #['TBD'] = ['TBD'].order_by()
        #return ['TBD'].all()

    def is_blocking(self, user):
        return self.blocked.filter(blocks.c.blocked_id == user.id).count() > 0

    def facebook_connect(self, facebook_id, facebook_name):
        self.facebook_id = facebook_id
        self.facebook_name = facebook_name

    def facebook_disconnect(self):
        self.facebook_id = None
        self.facebook_name = None

    def facebook_friends(self):
        """
        Find Facebook friends of this user who are also registered.
        """
        # Facebook will only return friends who also use this app.
        friends = facebook.get_friends(self.facebook_id)
        facebook_ids = [user['id'] for user in friends]
        # TODO: don't build this list with python! There must be a better way to do this with a query...
        friend_ids = [user.id for user in self.friends()]
        users = User.query.filter(User.facebook_id.in_(facebook_ids) & User.id.notin_(friend_ids))
        return users.all()

    def json(self, me, need_friendship=True, is_friend=None, has_sent_friend_request=None, has_received_friend_request=None):
        """
        Generate JSON representation of this user.

        :param me: User currently logged in. Necessary to generate boolean fields describing relationships.
        """
        raw = {key: getattr(self, key) for key in ('id', 'email', 'verified',
                                                   'facebook_id', 'facebook_name')}
        raw['name'] = self.facebook_name if self.facebook_name else self.name
        is_me = (self == me)
        raw.update({
            # Is this user me?
            'is_me': is_me,
            # Did this user receive/send a friend request from/to this user?
            'facebook_id': self.facebook_id,
            'facebook_name': self.facebook_name,
        })
        if need_friendship:
            if is_me:
                is_friend = False
                has_sent_friend_request = False
                has_received_friend_request = False
            else:
                if is_friend is None:
                    is_friend = self.is_friends_with(me)
                if is_friend:
                    has_sent_friend_request = False
                    has_received_friend_request = False
                if has_sent_friend_request is None:
                    has_sent_friend_request = self.has_sent_friend_request(me)
                if not has_sent_friend_request and has_received_friend_request is None:
                    has_received_friend_request = self.has_received_friend_request(me)
            raw.update({
                # Is the current user friends with this user?
                'is_friend': is_friend,
                'has_sent_friend_request': has_sent_friend_request,
                'has_received_friend_request': has_received_friend_request,
            })
        return raw


class BlacklistedToken(db.Model):
    __tablename__ = 'blacklisted_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.utcnow()

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistedToken.query.filter_by(token=str(auth_token)).first()
        return bool(res)


class Location(db.Model):
    __tablename__ = 'locations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Location
    location = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    address = db.Column(db.String(256), nullable=True)

    # Relationships
    updates = db.relationship('Update', backref='location', lazy=True)

    def update(self, raw):
        """
        Take dictionary of raw data and use it to set fields.
        """
        # TODO use set?
        for field in ('location', 'lat', 'lng', 'address',):
            if field in raw:
                setattr(self, field, raw[field])

    def __init__(self, raw, city_id):
        self.update(raw)
        self.city_id = city_id

    def people(self):
        return User.query.filter(User.current_location_id == self.id).count()


class Tag(db.Model):
    __tablename__ = 'tags'

    name = db.Column(db.String(32), primary_key=True)

    users = db.relationship(
        'User', secondary=taggings,
        backref=db.backref('tags', lazy='dynamic'), lazy='dynamic'
    )

    def __init__(self, name):
        self.name = name


class Update(db.Model):
    __tablename__ = 'updates'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    body = db.Column(db.String(1024))

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=False)

    def __init__(self, user, location):
        self.user_id = user.id
        self.location_id = location.id

    def json(self, me, include_location=False):
        raw = {
            'id': self.id,
            'body': self.body,
        }
        raw['user'] = self.user.json(me)
        if include_location:
            raw['location'] = self.location.json(me)
        return raw
