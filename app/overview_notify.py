"""Commit-time notifications for Overview; no scan/poll loop or traffic triggers."""
from app import db


def install():
    conn = db.get_conn()
    try:
        conn.execute("""
        CREATE OR REPLACE FUNCTION overview_notify() RETURNS trigger AS $$
        DECLARE topic text := TG_ARGV[0];
        BEGIN
          IF TG_TABLE_NAME = 'client_status_cache' AND TG_OP = 'UPDATE' THEN
            -- Byte counters and collection timestamps don't change Overview.
            IF (to_jsonb(NEW) - ARRAY['updated_at','session_bytes_recv','session_bytes_sent'])
              IS NOT DISTINCT FROM
               (to_jsonb(OLD) - ARRAY['updated_at','session_bytes_recv','session_bytes_sent']) THEN
              RETURN NULL;
            END IF;
          END IF;
          IF TG_TABLE_NAME = 'firewall_rules' THEN
            IF TG_OP = 'INSERT' AND NEW.kind <> 'client_block' THEN RETURN NULL; END IF;
            IF TG_OP = 'DELETE' AND OLD.kind <> 'client_block' THEN RETURN NULL; END IF;
            IF TG_OP = 'UPDATE' AND OLD.kind <> 'client_block' AND NEW.kind <> 'client_block' THEN RETURN NULL; END IF;
          END IF;
          IF TG_TABLE_NAME = 'vpn_events' AND TG_OP = 'INSERT' THEN
            IF NEW.event = 'other' AND btrim(NEW.detail) NOT LIKE 'OpenVPN 2.%%'
               AND btrim(NEW.detail) <> 'Initialization Sequence Completed' THEN RETURN NULL; END IF;
          END IF;
          PERFORM pg_notify('overview_changes', topic);
          RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """)
        for table, topic in [('client_status_cache', 'snapshot'), ('firewall_rules', 'snapshot'),
                             ('vpn_events', 'activity'), ('users', 'auth')]:
            # Identifiers and topics are fixed constants, never user input.
            conn.execute(f'DROP TRIGGER IF EXISTS overview_changed ON {table}')
            conn.execute(f"CREATE TRIGGER overview_changed AFTER INSERT OR UPDATE OR DELETE ON {table} "
                         f"FOR EACH ROW EXECUTE FUNCTION overview_notify('{topic}')")
        # Only clock-change evidence affects Overview among system log lines.
        conn.execute('DROP TRIGGER IF EXISTS overview_clock_changed ON system_log_lines')
        conn.execute("""CREATE TRIGGER overview_clock_changed AFTER INSERT ON system_log_lines
          FOR EACH ROW WHEN (NEW.process = 'systemd-resolved'
            AND NEW.message = 'Clock change detected. Flushing caches.')
          EXECUTE FUNCTION overview_notify('activity')""")
        conn.commit()
    finally:
        conn.close()
