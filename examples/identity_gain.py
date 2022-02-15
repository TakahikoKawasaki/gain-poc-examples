import yaml
import cherrypy
import yes
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("static"))

gain_config = yaml.load(open("config/gain.yml"), Loader=yaml.FullLoader)

idp_configs = {
    name: yes.YesConfiguration.from_dict(config)
    for name, config in gain_config["idps"].items()
}


class GAINExample:
    def _cp_dispatch(self, vpath):
        print(vpath)
        if vpath == ["yes", "oidccb"]:
            return self
        return vpath

    @cherrypy.expose
    def index(self):
        tmpl = env.get_template("index.html.j2")
        return tmpl.render(idp_configs=idp_configs)

    @cherrypy.expose
    def start(self, idp):
        """
        Starting the GAIN flow after the user clicked on the GAIN button.
        """
        config = idp_configs[idp]
        cherrypy.session["idp"] = idp

        yessession = yes.YesIdentitySession(
            gain_config["claims"], request_second_factor=False
        )
        cherrypy.session["yes"] = yessession
        yesflow = yes.YesIdentityFlow(config, cherrypy.session["yes"])

        yesflow.session.issuer_url = gain_config["idps"][idp]["issuer_url"]
        yesflow._retrieve_oauth_configuration()
        authz_parameters = yesflow._encode_authz_parameters()
        authz_url = yesflow._prepare_authz_url_traditional(authz_parameters)

        raise cherrypy.HTTPRedirect(authz_url)

    @cherrypy.expose
    def oidccb(self, iss, code=None, error=None, error_description=None):
        """
        OpenID Connect callback endpoint. The user arrives here after going
        through the authentication/authorizaton steps at the bank.

        Note that the URL of this endpoint has to be registered with yes for
        your client. 
        """
        configuration = idp_configs[cherrypy.session["idp"]]
        yesflow = yes.YesIdentityFlow(configuration, cherrypy.session["yes"])

        try:
            yesflow.handle_oidc_callback(iss, code, error, error_description)
        except yes.YesAccountSelectionRequested as exception:
            # user selected "select another bank" → must send user back to account chooser
            raise cherrypy.HTTPRedirect(exception.redirect_uri)
        except yes.YesError as exception:
            # not implemented here: show nice error messages
            raise cherrypy.HTTPError(400, str(exception))

        # id token and userinfo are alternative ways to retrieve user information - see developer guide
        user_data_id_token = yesflow.send_token_request()
        user_data_userinfo = yesflow.send_userinfo_request()

        tmpl = env.get_template("result.html.j2")
        return tmpl.render(
            idp_configs=idp_configs,
            user_data_id_token=user_data_id_token,
            user_data_userinfo=user_data_userinfo,
            dump=yaml.dump,
        )


cherrpy_config = {
    "global": {"server.socket_port": 3000},
    "/": {
        "tools.sessions.on": "True",
        "log.access_file": "access.log",
        "log.error_file": "error.log",
    },
}
cherrypy.quickstart(GAINExample(), "/", cherrpy_config)

