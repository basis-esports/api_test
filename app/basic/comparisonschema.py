from flask import Flask, jsonify, request, session, abort
from flask.ext.cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, orm, Index, func, select
from marshmallow import Schema, fields
from trueskill import Rating, rate_1vs1
import random

from . import UserSchema


class ComparisonSchema(Schema):

	evaluator = fields.Nested(UserSchema)
	male = fields.Nested(UserSchema)
	female = fields.Nested(UserSchema)
	position = fields.Nested(UserSchema)

	class Meta:
		model = Comparison
		fields = ("id", "evaluator", "male", "female", "position", "outcome")
		sqla_session = db.session