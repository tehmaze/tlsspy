import logging

logging.basicConfig(
    format='%(asctime)s %(module)s: %(message)s',
    level=logging.DEBUG,
)


def log(message, level=logging.INFO):
    if isinstance(level, basestring):
        level = getattr(logging, level.upper())

    logging.log(level, message)


def be_quiet():
    logger = logging.getLogger()
    logger.setLevel(logging.WARNING)


# Alias some of the logging facilities
logger       = logging.getLogger()

log.debug    = logger.debug
log.info     = logger.info
log.error    = logger.error
log.critical = logger.critical
log.warn     = logger.warning
log.warning  = logger.warning

log.quiet    = be_quiet
