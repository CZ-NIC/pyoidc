Examples of more advanced features
==================================

Requesting Claims using the "claims" Request Parameter
------------------------------------------------------

Specific claims can be requested using the Authorization request parameter::

    from oic.oic.message import ClaimsRequest, Claims

    claims_request = ClaimsRequest(
            id_token=Claims(email={"essential": None}, phone_number=None),
            userinfo=Claims(given_name={"essential": True},
                            family_name={"essential": True}, nickname=None)
    )

    request_args = {
        "redirect_uri": "https://example.com/rp/authz_cb",
        "scope": "openid",
        "response_type": "code",
        "claims": claims_request
    }

    # client is oic.oic.Client
    client.construct_AuthorizationRequest(request_args=request_args)