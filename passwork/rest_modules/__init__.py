from loguru import logger


def is_failed_status_code(status_code: int, prefix: str = ""):
    if status_code != 200:
        logger.error(f"{prefix}, HTTP response status code code: {status_code} != 200")
        return True


def is_failed_log_in_status_code(status_code: int):
    match status_code:
        case 200:
            logger.success("Logon successful, temporary API Token received")
        case 400:
            logger.error(
                "Logon error, possibly MASTER_PASSWORD is specified with client-side encryption disabled"
            )
        case 401:
            logger.error(
                "Logon error, possibly wrong API_KEY is specified"
            )
        case 404:
            logger.error(
                "Logon error, possibly wrong HOST is specified"
            )
        case _:
            logger.error(f"Logon error, HTTP response status code {status_code} != 200")

    if status_code != 200:
        return True
