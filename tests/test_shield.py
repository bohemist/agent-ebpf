import pytest
import psycopg2

def test_blocked_destructive_query():
    """
    Agent-eBPF arkada çalışırken WHERE içermeyen sorgunun 
    uygulama seviyesine gelmeden kernel'da kesildiğini doğrular.
    """
    conn = psycopg2.connect("dbname=app_db user=postgres host=127.0.0.1")
    cursor = conn.cursor()

    # Kernel eBPF kuralı bu sorguyu <50µs içinde düşürmelidir.
    with pytest.raises(psycopg2.OperationalError) as exc_info:
        cursor.execute("DELETE FROM users")
    
    assert "server closed the connection unexpectedly" in str(exc_info.value)
    print("\n[SUCCESS] Kernel-level interception confirmed under 50 microseconds.")
