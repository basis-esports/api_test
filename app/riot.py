from app import app
from riotwatcher import LolWatcher, ApiError


# global variables
# api_key = 'RGAPI-xxxxx'
# watcher = LolWatcher(api_key)
# user_region = 'na1'


class Riot:
    lol_watcher = LolWatcher(access_token=app.config['RIOT_GAMES_API_KEY'])
    user_region = 'na1'

    def get_summoner(self, summoner_id):
        return self.lol_watcher.summoner.by_name(user_region, summoner_id)

    def get_ranked_stats(self, summoner_id):
        return self.lol_watcher.league.by_summoner(user_region, get_summoner(['id']))

riot = Riot()
