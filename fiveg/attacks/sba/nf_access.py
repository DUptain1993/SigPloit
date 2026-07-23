#!/usr/bin/env python3
'''
NF Unauthorized Access / Token Enforcement check (5G SBI / HTTP2).

Service Based Architecture mandates OAuth2 access-token authorization between NFs
(3GPP TS 33.501).  This probe sends a request to a target NF service endpoint
first WITHOUT a token and then, if one is configured, WITH it - and reports
whether the endpoint enforces authorization.

An endpoint that returns 2xx to the token-less request is exposing a service
operation without access control.

    main(config_file, target, listening, verbosity, output_file)
'''
from fiveg.sba_core.sba_config_parser import SbaConfig
from fiveg.sba_core.sba_client import SbaClient, SbaError
from fiveg.commons.utilities import logOk, logErr, logWarn, logInfo

TAG = 'NF-ACCESS'


def _probe(base_url, path, token, verify, timeout):
    client = SbaClient(base_url, token=token, verify=verify, timeout=timeout)
    try:
        resp = client.get(path)
        return resp.status_code
    finally:
        client.close()


def main(config_file, target, listening=True, verbosity=2,
         output_file=None):
    if not config_file:
        logErr('Set a config file ("set config <file>") describing the target NF.',
               TAG=TAG)
        return
    try:
        cfg = SbaConfig(config_file)
    except Exception as e:
        logErr('Bad config: %s' % e, TAG=TAG)
        return

    base_url = cfg.base_url()
    path = cfg.service_path
    logInfo('Probing %s%s ...' % (base_url, path), TAG=TAG)

    try:
        no_token = _probe(base_url, path, None, cfg.verify_tls, cfg.timeout)
    except SbaError as e:
        logErr(str(e), TAG=TAG)
        return
    except Exception as e:
        logErr('Request failed: %s' % e, TAG=TAG)
        return

    logInfo('No-token request  -> HTTP %s' % no_token, TAG=TAG)

    if no_token is not None and 200 <= no_token < 300:
        logWarn('Endpoint served a request with NO access token (HTTP %s). '
                'Recommendation: enforce OAuth2 bearer-token authorization on '
                'every SBI service operation (TS 33.501) and terminate SBI mutual '
                'TLS at the NF/SEPP.' % no_token, TAG=TAG)
    elif no_token in (401, 403):
        logOk('Endpoint correctly rejected the token-less request (HTTP %s).'
              % no_token, TAG=TAG)
    else:
        logInfo('Endpoint returned HTTP %s to the token-less request.' % no_token,
                TAG=TAG)

    if cfg.token:
        try:
            with_token = _probe(base_url, path, cfg.token, cfg.verify_tls,
                                cfg.timeout)
            logInfo('With-token request -> HTTP %s' % with_token, TAG=TAG)
        except Exception as e:
            logErr('Token request failed: %s' % e, TAG=TAG)
    return no_token
