"""Operational script to verify PostgreSQL connectivity and list database objects."""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

import psycopg2
from dotenv import load_dotenv
from psycopg2 import OperationalError, ProgrammingError


def main() -> None:
    """Test the configured PostgreSQL connection and print a basic inventory."""
    load_dotenv()

    database_url = os.getenv("PSHIELD_DATABASE_URL")
    if not database_url:
        print("ERROR: PSHIELD_DATABASE_URL not found in .env")
        raise SystemExit(1)

    try:
        parsed_url = urlparse(database_url)
        host = parsed_url.hostname or "localhost"
        port = parsed_url.port or 5432
        user = parsed_url.username or "postgres"
        password = parsed_url.password
        database = parsed_url.path.lstrip("/")

        print("=" * 60)
        print("PostgreSQL Connection Test")
        print("=" * 60)
        print("\nConnection details:")
        print(f"   Host: {host}")
        print(f"   Port: {port}")
        print(f"   User: {user}")
        print(f"   Database: {database}")
        print(f"   Password: {'*' * len(password) if password else 'Not set'}\n")

    except Exception as exc:
        print(f"ERROR parsing DATABASE_URL: {exc}")
        raise SystemExit(1)

    try:
        print("Attempting to connect to database...")
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
        )
        cursor = conn.cursor()
        print(f"Successfully connected to '{database}'\n")

        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print("PostgreSQL version:")
        print(f"   {version}\n")

        cursor.execute(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name;
            """
        )
        tables = cursor.fetchall()

        if tables:
            print("Tables in current database:")
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table[0]};")
                row_count = cursor.fetchone()[0]
                print(f"   - {table[0]} ({row_count} rows)")
        else:
            print("No tables found in this database.")

        cursor.close()
        conn.close()
        print("\nAll tests passed.")

    except OperationalError as exc:
        print(f"Connection Error: {exc}")
        print("\nTroubleshooting:")
        print("   1. Verify PostgreSQL is running")
        print("   2. Verify host, port, user, and password in .env are correct")
        print("   3. Verify the database exists or will be created during migration")
        raise SystemExit(1)

    except ProgrammingError as exc:
        print(f"Programming Error: {exc}")
        raise SystemExit(1)

    except Exception as exc:
        print(f"Unexpected Error: {exc}")
        raise SystemExit(1)

    print("\n" + "=" * 60)
    print("Testing Server-Level Connection")
    print("=" * 60 + "\n")

    try:
        print("Attempting to connect to PostgreSQL server...")
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database="postgres",
        )
        cursor = conn.cursor()
        print("Successfully connected to PostgreSQL server\n")

        cursor.execute(
            """
            SELECT datname,
                   pg_database.datdba,
                   pg_size_pretty(pg_database_size(datname)) as size
            FROM pg_database
            ORDER BY datname;
            """
        )
        databases = cursor.fetchall()

        print("Available databases:")
        print(f"{'Database Name':<30} {'Owner ID':<15} {'Size':<15}")
        print("-" * 60)
        for db in databases:
            print(f"{db[0]:<30} {db[1]:<15} {db[2]:<15}")

        cursor.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s;",
            (database,),
        )
        if cursor.fetchone():
            print(f"\nTarget database '{database}' EXISTS")
        else:
            print(f"\nTarget database '{database}' DOES NOT EXIST")
            print("   It will be created during application initialization or migration")

        cursor.close()
        conn.close()
        print("\nServer connection test passed.")

    except OperationalError as exc:
        print(f"Server Connection Error: {exc}")
        raise SystemExit(1)

    except Exception as exc:
        print(f"Unexpected Error: {exc}")
        raise SystemExit(1)

    print("\n" + "=" * 60)
    print("All database tests completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    sys.exit(main())
