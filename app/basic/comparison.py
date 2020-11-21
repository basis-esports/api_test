from flask import Flask, jsonify, request, session, abort
from flask.ext.cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, orm, Index, func, select
from marshmallow import Schema, fields
from trueskill import Rating, rate_1vs1
import random


class Comparison(db.Model):
	__tablename__ = 'Comparisons'

	id = db.Column(db.Integer, primary_key=True)

	evaluator_id = db.Column(db.BigInteger, db.ForeignKey(User.id, on_delete=models.PROTECT), nullable=FALSE)
	evaluator = db.relationship(
		User, primaryjoin=evaluator_id == User.id,
		backref=orm.backref('comparison', lazy='dynamic')
	)

	male_id = db.Column(db.BigInteger, db.ForeignKey(User.id, on_delete=models.PROTECT), nullable=False)
	male = db.relationship(User, primaryjoin=male_id == User.id)

	female_id = db.Column(db.BigInteger, db.ForeignKey(User.id, on_delete=models.PROTECT), nullable=False)
	female = db.relationship(User, primaryjoin=female_id == User.id)

	position_id = db.Column(db.BigInteger, db.ForeignKey(User.id, on_delete=models.PROTECT), nullable=False)
	position = db.relationship(User, primaryjoin=position_id == User.id)

	outcome = db.Column(
		db.Enum("open","equal","male","female"),
		default="open", server_default="open",
	)

	__table_args__ = (
		Index("udx_single_comparisons", evaluator_id, male_id, female_id, position_id, unique=True),
	)