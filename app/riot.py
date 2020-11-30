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

    def __init__(self, summoner_name, summoner_region, current_tier, current_rank, summoner_points):
    	self.summoner_name = summoner_name
    	self.summoner_region = summoner_region
    	self.current_tier = current_tier
    	self.current_rank = current_rank
    	self.summoner_points = summoner_points

    def summoner_name():


    def statgatherer():
    	global element
    	current_rank = (element['tier'] + ' ' + element['rank'])
    	points = (element['leaguePoints'])



# test
lol_watcher = LolWatcher('RGAPI-96d87b95-6f83-4250-81b1-eec48daaa5a7')

my_region = 'na1'

me = lol_watcher.summoner.by_name(my_region, 'doublelift')

my_ranked_stats = lol_watcher.league.by_summoner(my_region, me['id'])

#for element in my_ranked_stats:
#	if element['queueType'] == 'RANKED_SOLO_5x5':
#		statgatherer()
#	else:
#		print('Error - no data found - check server, and summoner name.')

print(my_ranked_stats[0]['tier'])
