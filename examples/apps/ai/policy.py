"""SYNTHETIC AI boundary model. No model, MCP process or tool is launched."""
ALLOWED_TOOLS = {'read_note': {'approval': False}, 'prepare_export': {'approval': True}}


def retrieve(index, principal, query):
    return index.search(query, filters={'tenant_id': principal['tenant_id'], 'owner_id': principal['id']}, limit=5)


def propose_tool(name, arguments, principal, has_approval, stopped):
    if stopped or name not in ALLOWED_TOOLS or not isinstance(arguments, dict):
        raise PermissionError('Tool unavailable')
    if set(arguments) != {'note_id'} or not isinstance(arguments['note_id'], str):
        raise ValueError('Tool schema mismatch')
    if ALLOWED_TOOLS[name]['approval'] and not has_approval(principal, name, arguments):
        raise PermissionError('Independent approval required')
    # Result is a proposal. The backend repeats current object/tenant authorization.
    return {'tool': name, 'arguments': arguments, 'actor_id': principal['id'],
            'tenant_id': principal['tenant_id'], 'auth_version': principal['auth_version']}


def conversation_key(principal, conversation_id):
    return (principal['tenant_id'], principal['id'], principal['auth_version'], conversation_id)
