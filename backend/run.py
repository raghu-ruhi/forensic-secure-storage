from app import create_app
from app.db_bootstrap import seed_initial_admin

app = create_app()

if __name__ == "__main__":
    # The schema is managed ONLY by Flask-Migrate (`flask db upgrade`); the app
    # never creates or alters tables at startup.
    with app.app_context():
        seed_initial_admin()
    # The Werkzeug debugger allows remote code execution; never enable it in production.
    app.run(host="0.0.0.0", port=5000, debug=not app.config.get("IS_PRODUCTION"))
