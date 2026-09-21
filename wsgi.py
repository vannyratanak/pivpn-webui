from app import create_app

app = create_app()

if __name__ == "__main__":
    import config
    ssl_context = (config.BIND_TLS_CERT, config.BIND_TLS_KEY) if config.BIND_TLS_CERT and config.BIND_TLS_KEY else None
    # threaded=True: Werkzeug's dev server otherwise handles exactly one
    # connection at a time — a single idle keep-alive connection (Safari
    # and Chrome both hold HTTPS connections open for reuse) then blocks
    # every other client, including a second device, until it times out.
    # Caught live: a browser tab left open on this Mac silently blocked a
    # phone on the same network from loading the page at all.
    app.run(host=config.BIND_HOST, port=config.BIND_PORT, ssl_context=ssl_context, threaded=True)
