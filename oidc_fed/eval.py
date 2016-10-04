def verify_signature(ms, keys):
    pass


def html_get(uri):
    return ''


def get_keys(statement):
    if 'signing_keys' in statement:
        return statement['signing_keys']
    elif 'signing_keys_uri' in statement:
        return html_get(statement['signing_keys_uri'])
    else:
        return None


def verify(ms, fo_sign_keys):
    keys = []
    if 'metadata_statements' in ms:
        for statement in ms['metadata_statements']:
            if verify(statement, fo_sign_keys):
                keys.append(get_keys(statement))
    elif 'metadata_statement_uris':
        for iss, uri in ms.items():
            statement = html_get(uri)
            if verify(statement, fo_sign_keys):
                keys.append(get_keys(statement))
    else:
        return verify_signature(ms, fo_sign_keys)

    return  verify_signature(ms, keys)
