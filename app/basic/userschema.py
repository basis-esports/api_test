from flask import Flask, jsonify, request, session, abort
from flask.ext.cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, orm, Index, func, select
from marshmallow import Schema, fields
from trueskill import Rating, rate_1vs1
import random


class UserSchema(Schema):
	class Meta:
		model = User
		fields = ('id', 'name', 'profilePic', 'age', 'gender', 'position', 'score', 'sigma', 'sweaty')
		sqla_session = db.session