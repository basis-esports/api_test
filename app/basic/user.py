from flask import Flask, jsonify, request, session, abort
from flask.ext.cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, orm, Index, func, select
from marshmallow import Schema, fields
from trueskill import Rating, rate_1vs1
import random


class User(db.Model):
	__tablename__ = 'Users'

	# The user id is the facebook id of the user
	id = db.Column(db.BigInteger, primary_key=True, autoincrement=False)

	name = db.Column(db.String(100), nullable=False)
	profilePic = db.Column(db.String(250), nullable=False)
	gender = db.Column(db.Enum("male", "female"), nullable=False)
	age = db.Column(db.Integer)
	position = db.Column(db.String(100), nullable=False)

	score = db.Column(db.Float, default=25.0, server_default="25.0")
	sigma = db.Column(db.Float, default=8.333, server_default="8.333")

	@property
	def sweaty(self):
		minmax = db.engine.execute("SELECT MIN(score), MAX(score) FROM Users")

		low, high = minmax.fetchone()
		if low == high:
			return 10

		return (self.score - low) / (high - low) * 10
	