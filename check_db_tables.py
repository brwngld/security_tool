from dotenv import load_dotenv
import os
from sqlalchemy import create_engine, inspect, text
from app import _describe_database_target

load_dotenv('.env')
DATABASE_URL = os.getenv('PSHIELD_DATABASE_URL"')
if not DATABASE_URL:
    print('No PSHIELD_DATABASE_URL" set')
    raise SystemExit(1)

print('DATABASE_TARGET=', _describe_database_target(DATABASE_URL))

e = create_engine(DATABASE_URL)
with e.connect() as conn:
    try:
        tables = inspect(conn).get_table_names()
    except Exception as ex:
        print('Error inspecting database:', ex)
        raise
    print('Tables in database:', tables)
    # show count of some key tables
    for t in ['users','jobs','job_events','alembic_version']:
        if t in tables:
            try:
                c = conn.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
            except Exception as ex:
                c = f'error: {ex}'
        else:
            c = 'missing'
        print(f'{t}: {c}')
