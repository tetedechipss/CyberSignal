from app.database import init_db, DB_PATH

init_db()

print(f"Base de données initialisée : {DB_PATH}")