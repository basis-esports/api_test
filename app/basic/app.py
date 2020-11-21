from flask import Flask, jsonify, request, session, abort
from flask.ext.cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, orm, Index, func, select
from marshmallow import Schema, fields
from trueskill import Rating, rate_1vs1
import random


app = Flask(__name__)
app.config.update(
	SQLALCHEMY_DATABASE_URI="sqlite:///../test.db",
	SECRET_KEY="really-really-really-secret-key!",
	SESSION_COOKIE_HTTPONLY=False,
	CORS_SUPPORTS_CREDENTIALS=True,
)

CORS(app, resources=r'/api/')

db = SQLAlchemy(app)


@app.before_request
def set_current_user():
	if "userid" in session:
		user = User.query.get(int(session['userid']))
		if user is None:
			session.pop('userid')


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
	def sweat(self):
		minmax = db.engine.execute("SELECT MIN(score), MAX(score) FROM Users")

		low, high = minmax.fetchone()
		if low == high:
			return 10

		return (self.score - low) / (high - low) * 10


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


class UserSchema(Schema):
	class Meta:
		model = User
		fields = ('id', 'name', 'profilePic', 'age', 'gender', 'position', 'score', 'sigma', 'sweat')
		sqla_session = db.session

user_schema = UserSchema()


@app.route("/api/users/me")
def get_current_user():
	user = None
	if "userid" in session:
		user = User.query.get(session['userid'])

	return jsonify(user_schema.dump(user).data)


@app.route('/api/users/<id>')
def user_detail(id):
	user = User.query.get(id)
	if user is None:
		abort(404)

	res = user_schema.dump(user).data
	return jsonify(res)


@app.route("/api/users/<id>/matches")
def get_user_matches(id):
	user = User.query.get(id)
	if user is None:
		abort(404)

	subqry = select([User.id]).where(
		User.position != user.position
	).order_by(
		func.abs(User.score - user.score)
	).limit(5).alias()
	best_matches = User.query.join(subqry, subqry.c.id == User.id).all()

	res = user_schema.dump(best_matches, many=True).data
	return jsonify(results=res)


@app.route('/api/users', methods=['GET', 'POST', 'PUT'])
def users():
	if request.method == 'GET':
		res = user_schema.dump(User.query.all(), many=True).data
		return jsonify(results=res)

	elif request.method == 'POST':
		user = User(**user_schema.load(request.json).data)
		db.session.add(user)
		try:
			db.session.commit()
		except exc.IntegrityError:
			db.session.rollback()
			user = User.query.get(request.json['id'])

		session['userid'] = user.id
		return jsonify(user_schema.dump(user).data)

	elif request.method == 'PUT':
		parameters = user_schema.load(request.json).data
		user = User.query.get(parameters['id'])
		for k, v in parameters.iteritems():
			setattr(user, k, v)
		db.session.commit()
		return jsonify(user_schema.dump(user).data)


class ComparisonSchema(Schema):

	evaluator = fields.Nested(UserSchema)
	male = fields.Nested(UserSchema)
	female = fields.Nested(UserSchema)
	position = fields.Nested(UserSchema)

	class Meta:
		model = Comparison
		fields = ("id", "evaluator", "male", "female", "position", "outcome")
		sqla_session = db.session

comparison_schema = ComparisonSchema()


@app.route('/api/comparisons')
def comparisons():
	NUM_NEW_COMPS = 10

	evaluator_id = session.get('userid') or request.args.get('userid')
	evaluator_comparisons_qry = Comparison.query.filter_by(evaluator_id=evaluator_id)

	comparisons = []
	if evaluator_id is not None:
		open_comparisons = evaluator_comparisons_qry.filter_by(outcome="open").all()
		if len(open_comparisons) < NUM_NEW_COMPS:
			# Get all existing comparisons
			existing_comparisons = set(
				(c.male_id, c.female_id, c.position_id) for c in evaluator_comparisons_qry
			)

			# Get all users the evaluator has not yet compared
			all_males = []
			all_females = []
			all_positions = []
			all_users = db.session.query(User.id, User.gender, User.position).filter(
				User.id != evaluator_id
			).all()
			for userid, gender in all_users:
				target = all_males if gender == "male" else all_females
				target.append(userid)

			random.shuffle(all_males)
			random.shuffle(all_females)

			max_tries = (
				(len(all_males) - 1) * (len(all_females) - 1)
				- len(existing_comparisons)
			)
			tries = 0
			while (len(open_comparisons) < NUM_NEW_COMPS and tries < max_tries):
				tries += 1

				male, female = all_males.pop(0), all_females.pop(0), all_positions.pop(0)
				if (male, female, position) in existing_comparisons:
					all_males.append(male)
					all_females.append(female)
					all_positions.append(position)
					continue

				new_open_comparison = Comparison(
					evaluator_id=evaluator_id, male_id=male, female_id=female, position_id=position
				)
				db.session.add(new_open_comparison)
				db.session.flush()
				open_comparisons.append(new_open_comparison)

		db.session.commit()
		comparisons = comparison_schema.dump(open_comparisons, many=True).data

	return jsonify(results=comparisons)


@app.route('/api/comparisons/<int:comparison_id>', methods=['PUT'])
def update_comparison(comparison_id):
	comparison = Comparison.query.get(comparison_id)
	if comparison is None:
		abort(404)

	outcome = request.json.get('outcome')
	if outcome in (None, "open"):
		abort(404)

	comparison.outcome = outcome

	winner, loser = comparison.male, comparison.female, comparison.position
	if outcome == "female":
		winner, loser = loser, winner

	winner_rat = Rating(mu=winner.score, sigma=winner.sigma)
	loser_rat = Rating(mu=loser.score, sigma=loser.sigma)
	new_winner_rat, new_loser_rat = rate_1vs1(
		winner_rat, loser_rat, drawn=True if outcome == "equal" else False
	)

	winner.score = new_winner_rat.mu
	winner.sigma = new_winner_rat.sigma

	loser.score = new_loser_rat.mu
	loser.sigma = new_loser_rat.sigma

	db.session.commit()
	return jsonify(comparison_schema.dump(comparison).data)


@app.route('/api/teams')
def top_teams():
	results = []

	couples = db.engine.execute(
		"SELECT male_id, female_id, position_id, COUNT(*) AS no_of_equals"
		"	FROM Comparisons WHERE outcome ='equal'"
		"	GROUP BY male_id, female_id, position_id"
		"	ORDER BY COUNT(*) DESC LIMIT 10"
	)
	for r in teams.fetchall():
		results.append({
			'male': user_schema.dump(User.query.get(r.male._id)).data,
			'female': user_schema.dump(User.query.get(r.female_id)).data,
			'position': user_schema.dump(User.query.get(r.position_id)).data,
			'number_of_equals': r.no_of_equals,
		})

	return jsonify(results=results)


@app.route("/leDatabase", methods=["DELETE"])
def reset_db():
	db.drop_all()
	db.create_all()
	return "ok!"


if __name__ == '__main__':
	db.drop_all()
	db.create_all()
	app.run(host="0.0.0.0", debug=True)









