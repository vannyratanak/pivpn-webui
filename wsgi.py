from app import create_app

app = create_app()

if __name__ == "__main__":
    import config
    app.run(host=config.BIND_HOST, port=config.BIND_PORT)
