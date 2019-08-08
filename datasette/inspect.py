import asyncio
import hashlib

from .utils import (
    detect_spatialite,
    detect_fts,
    detect_primary_keys,
    escape_sqlite,
    get_all_foreign_keys,
    table_columns,
    sqlite3,
)

HASH_BLOCK_SIZE = 1024 * 1024


def inspect_hash(path):
    " Calculate the hash of a database, or the first 100Mb of it if larger, efficiently. "
    m = hashlib.sha256()
    print( "Hashing %s..." % path )
    count = 0
    with path.open("rb") as fp:
        while True and count < 100:
            data = fp.read(HASH_BLOCK_SIZE)
            if not data:
                break
            m.update(data)
            count = count + 1

    return m.hexdigest()


def inspect_views(conn):
    " List views in a database. "
    return [
        v[0] for v in conn.execute('select name from sqlite_master where type = "view"')
    ]

def execute_time_limited_query(
    conn,
    sql,
    time_limit_ms,
    params=None
):
    """Executes sql against db in a thread"""
    async def sql_operation_in_thread():
        #print( "Executing query with time limit: %d" % time_limit_ms )
        with sqlite_timelimit(conn, time_limit_ms):
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params or {})
                rows = cursor.fetchall()
            except sqlite3.OperationalError as e:
                if e.args == ('interrupted',):
                    raise InterruptedError(e)
                print(
                    "ERROR: conn={}, sql = {}, params = {}: {}".format(
                        conn, repr(sql), params, e
                    )
                )
                raise
            return rows ;
    return asyncio.get_event_loop().run_until_complete(
        sql_operation_in_thread()
    )


def inspect_tables(conn, database_metadata):
    " List tables and their row counts, excluding uninteresting tables. "
    tables = {}
    table_names = [
        r["name"]
        for r in conn.execute('select * from sqlite_master where type="table"')
    ]

    for table in table_names:
        print( "Inspecting %s..." % table )
        raise Exception( "AAAAGH" ) ;
        table_metadata = database_metadata.get("tables", {}).get(table, {})
        try:
            countRows = execute_time_limited_query( conn, "select count(*) from {}".format(escape_sqlite(table)), time_limit_ms = 1000 )
            count = countRows[0][0] ;
        except sqlite3.OperationalError:
            # This can happen when running against a FTS virtual table
            # e.g. "select count(*) from some_fts;"
            conn.set_progress_handler(None, 1000)
            count = 0
        except InterruptedError:
            # GB: Or this can happen if the query times out due to a large db.
            conn.set_progress_handler(None, 1000)
            count = None
        column_names = table_columns(conn, table)

        tables[table] = {
            "name": table,
            "columns": column_names,
            "primary_keys": detect_primary_keys(conn, table),
            "count": count,
            "hidden": table_metadata.get("hidden") or False,
            "fts_table": detect_fts(conn, table),
        }

    foreign_keys = get_all_foreign_keys(conn)
    for table, info in foreign_keys.items():
        tables[table]["foreign_keys"] = info

    # Mark tables 'hidden' if they relate to FTS virtual tables
    hidden_tables = [
        r["name"]
        for r in conn.execute(
            """
                select name from sqlite_master
                where rootpage = 0
                and sql like '%VIRTUAL TABLE%USING FTS%'
            """
        )
    ]

    if detect_spatialite(conn):
        # Also hide Spatialite internal tables
        hidden_tables += [
            "ElementaryGeometries",
            "SpatialIndex",
            "geometry_columns",
            "spatial_ref_sys",
            "spatialite_history",
            "sql_statements_log",
            "sqlite_sequence",
            "views_geometry_columns",
            "virts_geometry_columns",
        ] + [
            r["name"]
            for r in conn.execute(
                """
                    select name from sqlite_master
                    where name like "idx_%"
                    and type = "table"
                """
            )
        ]

    for t in tables.keys():
        for hidden_table in hidden_tables:
            if t == hidden_table or t.startswith(hidden_table):
                tables[t]["hidden"] = True
                continue

    return tables
