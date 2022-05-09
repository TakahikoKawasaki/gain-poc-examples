from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import requests
import cherrypy
import yaml
import yes
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("static"))

gain_config = yaml.load(open("config/gain.yml"), Loader=yaml.FullLoader)


@dataclass
class GAINConfiguration(yes.YesConfiguration):
    client_secret: Optional[str] = None

    def __post_init__(self):
        if self.client_secret:
            return
        if not Path(self.cert_file).exists() or not Path(self.key_file).exists():
            raise Exception(
                f"Please provide a certificate and private key pair at the following "
                f"locations: {self.cert_file} / {self.key_file} or change the locations "
                f"in the configuration."
            )

    @staticmethod
    def from_dict(dct):
        return GAINConfiguration(
            client_id=dct["client_id"],
            cert_file=dct["cert_file"],
            key_file=dct["key_file"],
            redirect_uri=dct["redirect_uri"],
            environment=dct.get("environment", "sandbox"),
            qtsp_id=dct.get("qtsp_id"),
            authz_style=yes.YesAuthzStyle.PUSHED
            if (dct.get("authz_style", "pushed") == "pushed")
            else yes.YesAuthzStyle.FRONTEND,
            client_secret=dct.get("client_secret", None),
        )


idp_configs = {
    name: GAINConfiguration.from_dict(config)
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
        NOTE: The iss parameter is not yet supported by BankID and Dizme. This
        is a workaround for now.
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

    def send_token_request(self) -> Optional[Dict]:
        """
        NOTE: This method is overridden to support IDPs that do not yet support
        MTLS for client authentication. This is not compliant to the current
        GAIN specification.
        """

        token_endpoint = self.session.oauth_configuration["token_endpoint"]
        token_parameters = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code": self.session.authorization_code,
            "code_verifier": self.session.pkce.verifier,
        }

        if self.config.client_secret:
            token_parameters["client_secret"] = self.config.client_secret
            req = requests.post(
                token_endpoint,
                data=token_parameters,
            )
        else:
            req = requests.post(
                token_endpoint,
                data=token_parameters,
                cert=self.cert_config,
            )

        self.log.debug(f"Sent token request: {token_parameters}")

        token_response = self._decode_or_raise_error(
            req,
            is_oauth=True,
        )

        self._debug_token_response = token_response

        self.session.access_token = token_response["access_token"]

        if "authorization_details" in token_response:
            self.session.authorization_details_enriched = token_response[
                "authorization_details"
            ]

        if "id_token" in token_response:
            return self._decode_and_validate_id_token(token_response["id_token"])
        else:
            return

    def send_userinfo_request(self) -> Dict:
        """
        NOTE: This method is overridden to support IDPs that do not yet support
        MTLS for client authentication. This is not compliant to the current
        GAIN specification.
        """
        if not self.session.access_token:
            raise Exception(
                "No access token found. send_token_request must be used first to retrieve an access token."
            )

        if self.config.client_secret:
            return self._decode_or_raise_error(
                requests.get(
                    self.session.oauth_configuration["userinfo_endpoint"],
                    headers={
                        "Authorization": f"Bearer {self.session.access_token}",
                        "accept": "*/*",
                    },
                ),
                is_oauth=True,
            )
        else:
            return self._decode_or_raise_error(
                requests.get(
                    self.session.oauth_configuration["userinfo_endpoint"],
                    headers={
                        "Authorization": f"Bearer {self.session.access_token}",
                        "accept": "*/*",
                    },
                    cert=self.cert_config,
                ),
                is_oauth=True,
            )


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
        self,
        iss=None,
        code=None,
        error=None,
        error_description=None,
        state=None,
        **kwargs,
    ):
        """
        OpenID Connect callback endpoint. The user arrives here after going
        through the authentication/authorizaton steps at the bank.

        Note that the URL of this endpoint has to be registered with the GAIN
        IDP for your client.
        """
        configuration = idp_configs[cherrypy.session["idp"]]
        gainflow = GAINFlow(configuration, cherrypy.session["gain"])

        gainflow.handle_oidc_callback(iss, code, error, error_description)

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
