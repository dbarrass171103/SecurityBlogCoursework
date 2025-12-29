import logging
from logging.handlers import RotatingFileHandler

def start_logger():
    logger = logging.getLogger("security_logger")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler("security.log", maxBytes=1000000, backupCount= 3)
    handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s : %(message)s")
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger
