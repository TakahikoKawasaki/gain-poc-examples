from datetime import datetime
from typing import Dict, Optional
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


class GAINSession(yes.YesIdentitySession):
    def __init__(self, claims: Dict):
        """
        NOTE: The supported ACR values differ from those in the yes ecosystem!
        This disables the ACR check in the ID token.
        """

        super().__init__(claims, False)
        self.acr_values = []


class GAINFlow(yes.YesIdentityFlow):
    def start_gain_flow(self, issuer) -> str:
        self.session.issuer_url = issuer
        self._retrieve_oauth_configuration()
        authz_parameters = self._encode_authz_parameters()
        authz_url = self._prepare_authz_url_traditional(authz_parameters)
        return authz_url

    def _assemble_authz_parameters(self) -> Dict:
        """
        NOTE: PKCE and Nonce are used, state is not needed, but enforced by
        BankID. This adds a dummy state to the authorization request.
        """

        authz_parameters = super()._assemble_authz_parameters()
        authz_parameters["state"] = "dummy"
        return authz_parameters

    def handle_oidc_callback(
        self,
        iss: str,
        code: Optional[str] = None,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
    ):
        """
        NOTE: The iss parameter is not yet supported by BankID. This is a
        workaround for now.
        """

        if iss is None:
            print("WARNING: No mix-up protection!")
            iss = self.session.issuer_url
        return super().handle_oidc_callback(iss, code, error, error_description)

    def _decode_and_validate_id_token(self, id_token_encoded: str) -> Dict:
        """
        NOTE: BankID sets a very tight not-before timestamp in the ID token -
        ensure that there is no clock skew! Check at https://time.is!

        Added debugging information here to find the issue:
        """

        print(f"Decoding and validating id_token: {id_token_encoded}")
        print(f"Current unix timestamp: {datetime.now().timestamp()}")
        return super()._decode_and_validate_id_token(id_token_encoded)


class GAINExample:
    def _cp_dispatch(self, vpath):
        """
        Ensure that the path /yes/oidccb is mapped to the oidccb function below.
        """
        if vpath == ["yes", "oidccb"]:
            return self
        return vpath

    @cherrypy.expose
    def index(self):
        """
        Serve the start page, listing the available IDPs.
        """
        tmpl = env.get_template("index.html.j2")
        return tmpl.render(idp_configs=idp_configs)

    @cherrypy.expose
    def start(self, idp):
        """
        Starting the GAIN flow after the user clicked on the GAIN button.
        """
        config = idp_configs[idp]
        cherrypy.session["idp"] = idp

        gainsession = GAINSession(gain_config["claims"])
        cherrypy.session["gain"] = gainsession
        
        gainflow = GAINFlow(config, cherrypy.session["gain"])
        authz_url = gainflow.start_gain_flow(gain_config["idps"][idp]["issuer_url"])
        raise cherrypy.HTTPRedirect(authz_url)

    @cherrypy.expose
    def oidccb(
        self, iss=None, code=None, error=None, error_description=None, state=None
    ):
        """
        OpenID Connect callback endpoint. The user arrives here after going
        through the authentication/authorizaton steps at the bank.

        Note that the URL of this endpoint has to be registered with the GAIN
        IDP for your client. 
        """
        configuration = idp_configs[cherrypy.session["idp"]]
        gainflow = GAINFlow(configuration, cherrypy.session["gain"])

        try:
            gainflow.handle_oidc_callback(iss, code, error, error_description)
        except yes.YesAccountSelectionRequested as exception:
            # user selected "select another bank" → must send user back to account chooser
            raise cherrypy.HTTPRedirect(exception.redirect_uri)
        except yes.YesError as exception:
            # not implemented here: show nice error messages
            raise cherrypy.HTTPError(400, str(exception))

        # id token and userinfo are alternative ways to retrieve user information - see developer guide
        user_data_id_token = gainflow.send_token_request()
        user_data_userinfo = gainflow.send_userinfo_request()

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

