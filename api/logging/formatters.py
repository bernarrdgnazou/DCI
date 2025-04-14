import json
import logging
import traceback
from datetime import datetime

class JSONFormatter(logging.Formatter):
    """
    Formatter personnalisé qui produit des logs au format JSON
    """
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'path': record.pathname,
            'lineno': record.lineno,
            'func': record.funcName,
        }
        
        # Ajouter les infos d'exception si présentes
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Ajouter d'autres attributs personnalisés
        for key, value in record.__dict__.items():
            if key not in ['args', 'asctime', 'created', 'exc_info', 'exc_text', 
                           'filename', 'funcName', 'id', 'levelname', 'levelno',
                           'lineno', 'module', 'msecs', 'message', 'msg', 'name',
                           'pathname', 'process', 'processName', 'relativeCreated',
                           'stack_info', 'thread', 'threadName']:
                log_data[key] = value
        
        return json.dumps(log_data)