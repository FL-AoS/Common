"""
Dependencies: requests

Website API for updating highscores, login, register, etc

config.toml:
[website_api]
token = ""
url = ""

Events added:
Connection.on_website_login()
"""
from piqueserver.commands import command
from piqueserver.config import config
import requests
import json

WB_CFG = config.section("website_api")
URL = WB_CFG.option("url", default="http://127.0.0.1:8000").get()
TOKEN = WB_CFG.option("token").get()

LOGIN_ENDPOINT = URL+"/api/server/login/validate"
HIGHSCORE_UPLOAD_ENDPOINT = URL+"/api/server/highscores/upload"

HEADERS = {
	"Content-Type": 'application/json',
	"Accept": 'application/json',
	"Authorization": "Bearer "+TOKEN
}

@command("login")
def login(p, user=None, passw=None):
	if not passw:
		for user_type, passwords in p.protocol.passwords.items():
			#yes isnt actually the user, but yes
			if user in passwords:
				if user_type in p.user_types:
					return "You're already logged in as %s" % user_type
				return p.on_user_login(user_type, True)

		if p.login_retries is None:
			p.login_retries = p.protocol.login_retries - 1
		else:
			p.login_retries -= 1

		if not p.login_retries:
			p.kick('Ran out of login attempts')
			return

		return 'Use /login <user> <password>. If you not has an account use /register'

	login_obj = {
		"login": user,
		"password": passw,
		"ip": p.address[0]
	}

	resp = requests.get(LOGIN_ENDPOINT, headers=HEADERS, json=login_obj)

	if not resp or resp.status_code != 200:
		return "Wrong infos for login..."

	resp_obj = resp.json()
	p.logged_user_id = resp_obj["id"]

	p.on_website_login()

	return "Welcome back %s!"%(user)

def apply_script(protocol, connection, config):
	class WebsiteConnection(connection):
		logged_user_id = None

		def on_website_login(self):
			pass

	class WebsiteProtocol(protocol):
		def upload_player_highscores(self, obj):
			requests.post(HIGHSCORE_UPLOAD_ENDPOINT, headers=HEADERS, json=obj)

	return WebsiteProtocol, WebsiteConnection