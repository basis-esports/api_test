import requests
from riotwatcher import LolWatcher, ApiError

RIOT_GAMES_API_KEY = os.environ.get('RIOT_GAMES_API_KEY')


class Summoner(db.Model):
	__tablename__ = 'summoners'

	id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)

	summoner_name = db.Column(db.String(64), nullable=False)
	summoner_region = db.Column(db.String(64), nullable=False)
	current_tier = db.Column(db.String(64), nullable=False)
	current_rank = db.Column(db.String(64), nullable=False)
	summoner_points = db.Column(db.BigInteger, nullable=False)

    lol_watcher = LolWatcher(access_token=app.config['RIOT_GAMES_API_KEY'])

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def update(self, raw):
    	for field in ('summoner_name'):
    		if field in raw:
    			setattr(self, field, raw[field])

    def __init__(self, summoner_name, summoner_region, current_tier, current_rank, summoner_points):
    	self.summoner_name = summoner_name
    	self.summoner_region = summoner_region
    	self.current_tier = current_tier
    	self.current_rank = current_rank
    	self.summoner_points = summoner_points

    # Launch stat tree - load server list, then load rank stats
	def launchstattree(self,):
		global element
		from lib import apisettings

		lol_watcher = LolWatcher(apisettings.yourapikey)

		serverselect()

		me = lol_watcher.summoner.by_name(my_region, sumname)

		my_ranked_stats = lol_watcher.league.by_summoner(my_region, me['id'])

		for element in my_ranked_stats:
			if element['queueType'] == 'RANKED_SOLO_5x5':
				gather_stats()
		else:
			return fail('Error - no data found - check server, and summoner name.')


# test
lol_watcher = LolWatcher('RGAPI-96d87b95-6f83-4250-81b1-eec48daaa5a7')

my_region = 'na1'

me = lol_watcher.summoner.by_name(my_region, 'doublelift')

my_ranked_stats = lol_watcher.league.by_summoner(my_region, me['id'])

print(my_ranked_stats[0]['tier'])


# Launches menu, using pick to allow the player to select what they want to do
def summoner_name():
	global sumname

	sumname = input('Your summoner name: ')
	sumname = sumname.translate(dict.fromkeys(map(ord, whitespace)))
	launchstattree()


# Gathers stats
def gather_stats():
	global element
	current_tier = element['tier']
	current_rank = element['rank']
	points = (element['leaguePoints'])
	wins = (element['wins'])
	losses = (element['losses'])
	total_games = wins + losses
	rate = round(wins * 100 / total_games, 2)
	summoner_name()
