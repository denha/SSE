def response(message, status, data=None):
    return {'msg': str(message), 'status': status, 'data': data}