from flask import Blueprint, jsonify, request, session, abort, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, orm, Index, func, select
from marshmallow import Schema, fields
from trueskill import Rating, rate_1vs1
from werkzeug.utils import secure_filename

from app import db
from app.models import User, Location, Tag, Update, friendships, friend_requests, Comparison, UserSchema, ComparisonSchema
from app.geography import searching
from app.util import succ, fail
from app.notifier import notifier
from app.facebook import facebook
from app.images import image_upload

from io import BytesIO

import datetime
import os
import json
import random


api = Blueprint('api', __name__)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


@api.errorhandler(404)
def not_found(error):
    return fail('Not found.', 404)


@api.errorhandler(401)
def unauthorized(error):
    return fail('You\'re not authorized to perform this action.', 401)


@api.errorhandler(403)
def forbidden(error):
    return fail('You don\'t have permission to do this.', 403)


@api.before_request
def verify_token():
    if request.method != 'OPTIONS':
        token = request.headers.get('Authorization', request.args.get('token', None))
        if token is None:
            abort(401)
        token = token.split(' ')[-1]
        g.me = User.from_token(token)
        if g.me is None:
            abort(401)
        g.me.last_seen = datetime.datetime.utcnow()
        db.session.commit()
        print('User: ' + g.me.name)
        g.json = request.get_json()
# def set_current_user():
#     if "userid" in session:
#         user = User.query.get(int(session['userid']))
#         if user is None:
#             session.pop('userid')


#################
# Miscellaneous #
#################

@api.route('/heartbeat')
def heartbeat():
    return jsonify({
        'maintenance': bool(os.environ.get('MAINTENANCE', False)),
        'min_version': 0,
    })


# determine how to use this for users as well
@api.route('/location', methods=['POST'])
def update_location():
    lat = g.json['lat']
    lng = g.json['lng']
    # In order to save some processing, first check if the user is still at their current location
    # (which they probably will be a decent percentage of the time).
    if g.me.current_location_id is not None:
        location = Location.query.get(g.me.current_location_id)
        if searching(lat, lng, location.lat, location.lng):
            return succ('Location received, no location change.')

    g.me.current_location_id = None
    for location in g.me.feed():
        if (location.lat is not None and location.lng is not None) and searching(lat, lng, location.lat, location.lng):
            g.me.current_location_id = location.id
            break
    db.session.commit()
    return succ('Location received!')


@api.route('/status')
def about():
    return jsonify({
        'users': User.query.count(),
        'locations': Location.query.count(),
    })


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@api.route('/image', methods=['POST'])
def upload_image():
    image = request.data
    url = image_upload(image)
    return jsonify({'url': url})


#########
# Users #
#########

@api.route('/users/<user_id>')
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.json(g.me))


@api.route('/users/me')
def get_me():
    return jsonify(g.me.json(g.me, need_friendship=False))


@api.route('/users/me', methods=['PUT'])
def update_me():
    # TODO: make method of User
    g.me.name = g.json['name']
    db.session.commit()
    return succ('Updated profile.')


@api.route('/users/me/password', methods=['PUT'])
def update_password():
    old_password = g.json.get('old_password')
    new_password = g.json.get('new_password')
    if not old_password or not new_password:
        return fail('Improper parameters.')
    if g.me.is_password_correct(old_password):
        g.me.set_password(new_password)
        db.session.commit()
        return succ('Successfully updated password!')
    return fail('Incorrect password.', 403)


@api.route('/users/search/<query>')
def search_users(query):
    users = g.me.search(query)
    return jsonify([user.json(g.me) for user in users])


@api.route('/users/me/tags/<tag_name>', methods=['POST'])
def add_tag(user_id, tag_name):
    user = User.query.get_or_404(user_id)
    tag_name = tag_name.lower()
    if not (g.me.admin):
        abort(403)
    # First, check if the user already has this tag.
    if user.has_tag(tag_name):
        return fail('User already has this tag.')
    if user.add_tag(tag_name):
        db.session.commit()
        return succ('Added tag!')
    # If the tag is blacklisted or there was another problem
    return fail('Tag not added.')


@api.route('/users/me/tags/<tag_name>', methods=['DELETE'])
def remove_tag(user_id, tag_name):
    user = User.query.get_or_404(user_id)
    if not (g.me.admin):
        abort(403)
    if not user.has_tag(tag_name):
        return fail('User does not have this tag.')
    if user.remove_tag(tag_name):
        db.session.commit()
        return succ('Removed tag.')
    # Should not be reached, but just in case.
    return fail('Tag not removed.')


@api.route('/tags/search/<query>')
def search_tags(query):
    query = query.lower()
    tags = Tag.query.filter(User.name.ilike('%' + query + '%'))
    return jsonify([tag.name for tag in tags])


# Blocks
@api.route('/users/<user_id>/block', methods=['POST'])
def block_user(user_id):
    user = User.query.get(user_id)
    if g.me.block(user):
        db.session.commit()
        return succ('Succesfully blocked user.')
    else:
        return fail('You\'ve already blocked this person.')


@api.route('/users/<user_id>/block', methods=['DELETE'])
def unblock_user(user_id):
    user = User.query.get(user_id)
    if g.me.unblock(user):
        db.session.commit()
        return succ('Succesfully unblocked user.')
    else:
        return fail('You haven\'t blocked this person.')

# Games
@api.route('/users/me/games/<game_name>', methods=['POST'])
def add_game(user_id, game_name):
    user = User.query.get_or_404(user_id)
    if not (g.me.admin):
        abort(403)
    if user.has_game(game_name):
        return fail('User already plays this game.')
    if user.add_game(game_name):
        db.session.commit()
        return succ('Added game!')
    return fail('Game not added.')

@api.route('/users/me/games/<game_name>', methods=['DELETE'])
def remove_game(user_id, game_name):
    user = User.query.get_or_404(user_id)
    if not (g.me.admin):
        abort(403)
    if not user.has_game(game_name):
        return fail('User does not play this game.')
    if user.remove_game(game_name):
        db.session.commit()
        return succ('Game removed!')
    return fail('Game not removed.')

@api.route('/games/search/<query>')
def search_games(query):
    query = query.lower()
    games = Game.query.filter(User.name.ilike('%' + query + '%'))
    return jsonify([game.name for game in games])

# Facebook
@api.route('/users/me/facebook', methods=['POST'])
def facebook_connect():
    g.me.facebook_connect(g.json['id'], g.json['name'])
    db.session.commit()
    return succ('Successfully connected!')


@api.route('/users/me/facebook', methods=['DELETE'])
def facebook_disconnect():
    g.me.facebook_disconnect()
    db.session.commit()
    return succ('Successfully disconnected!')


# Friendships - change to match accept/reject
@api.route('/friends/<user_id>/request', methods=['POST'])
def create_friend_request(user_id):
    user = User.query.get_or_404(user_id)
    if g.me.friend_request(user):
        db.session.commit()
        notifier.friend_request(g.me, user)
        return succ('Succesfully sent friend request!')
    else:
        return fail('You\'re already friends with this person.')


@api.route('/friends/<user_id>/cancel', methods=['POST'])
def cancel_friend_request(user_id):
    friend_request_sent = g.me.friend_requests_sent.filter(friend_requests.c.friended_id == user_id).first_or_404()
    if friend_request_sent is not None:
        g.me.friend_requests_sent.remove(friend_request_sent)
    db.session.commit()
    return succ('Succesfully cancelled friend request.')


@api.route('/friends/<friender_id>/accept', methods=['POST'])
def accept_friend_request(friender_id):
    req = g.me.friend_requests_received.filter(friend_requests.c.friender_id == friender_id).first_or_404()
    friend = User.query.get(friender_id)
    friend.friended.append(g.me)
    g.me.friend_requests_received.remove(req)
    db.session.commit()
    notifier.accept_friend_request(g.me, friend)
    return succ('Accepted the request!')


@api.route('/friends/<user_id>/reject', methods=['POST'])
def reject_friend_request(user_id):
    """
    Decline a friend request.
    """
    req = g.me.friend_requests_received.filter(friend_requests.c.friender_id == user_id).first_or_404()
    g.me.friend_requests_received.remove(req)
    db.session.commit()
    return succ('Successfully rejected request.')


@api.route('/friends/<user_id>/remove', methods=['POST'])
def friend_remove(user_id):
    """
    Remove friendship.
    """
    friendship_sent = g.me.friended.filter(friendships.c.friended_id == user_id).first()
    friendship_received = g.me.frienders.filter(friendships.c.friender_id == user_id).first()
    if friendship_sent is None and friendship_received is None:
        return fail('Couldn\'t find a friendship with this person.')
    if friendship_sent is not None:
        g.me.friended.remove(friendship_sent)
    if friendship_received is not None:
        g.me.frienders.remove(friendship_received)
    db.session.commit()
    return succ('Succesfully removed friend.')


@api.route('/friends')
def get_friends():
    """
    Get friends of logged in user.
    """
    friends = g.me.friends()
    return jsonify([user.json(g.me, is_friend=True) for user in friends])


@api.route('/friends/requests')
def get_friend_requests():
    """
    Get users who have sent friend requests to the current user.
    """
    friend_requests = g.me.friend_requests()
    return jsonify([user.json(g.me, is_friend=False, has_received_friend_request=False, has_sent_friend_request=True) for user in friend_requests])


@api.route('/friends/facebook', methods=['GET'])
def get_facebook_friends():
    """
    Get a list of users who have connected to Facebook and are friends with this user there.
    """
    if g.me.facebook_id is None:
        return jsonify([])
    users = g.me.facebook_friends()
    return jsonify([user.json(g.me, is_friend=False) for user in users])


############
# Location #
############

@api.route('/locations')
def get_locations():
    locations = g.me.feed()
    return jsonify([location.json(g.me) for location in locations])


@api.route('/locations/<location_id>')
def get_location(location_id):
    location = Location.query.get_or_404(location_id)
    return jsonify(location.json(g.me))


@api.route('/locations/<location_id>', methods=['PUT'])
def update_location(location_id):
    location = Location.query.get_or_404(location_id)
    if not (g.me.admin):
        abort(403)
    location.update(g.json)
    db.session.commit()
    return jsonify(location.json(g.me)), 202


@api.route('/users/me/locations/current')
def get_my_current_location():
    if g.me.current_location_id is None:
        return jsonify([])
    location = Location.query.get(g.me.current_location_id)
    if location is None:
        return jsonify([])
    return jsonify([location.json(g.me)])


@api.route('/users/<user_id>/locations/current')
def get_user_current_location(user_id):
    # TODO: this is so repetitive stop
    user = User.query.get(user_id)
    if not g.me.is_friends_with(user):
        return fail('You must be friends with this user to view their location.', 403)
    if g.me.current_location_id is None:
        return jsonify([])
    location = Location.query.get(user.current_location_id)
    if location is None:
        return jsonify([])
    return jsonify([location.json(g.me)])


#############
#    TBD    #
#############




@api.route("/leDatabase", methods=["DELETE"])
def reset_db():
    db.drop_all()
    db.create_all()
    return "ok!"


if __name__ == '__main__':
    db.drop_all()
    db.create_all()
    app.run(host="0.0.0.0", debug=True)

