import ui
import state
import server
import logger


def main():
    logger.init("/tmp/bproxy.log")
    server.start(host="0.0.0.0", port=state.proxy_port)
    ui.get_user_cmd()
    server.stop()


if __name__ == "__main__":
    main()
