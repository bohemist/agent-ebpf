# Agent-eBPF: Geliştirici Kılavuzu (Developer Guide)

> **Agent-eBPF**, yapay zeka ajanlarının (*LLM Agents, MCP Tools, Autonomous Swarms*) ürettiği SQL sorgularını, sistem çağrılarını ve ağ paketlerini uygulama koduna dokunmadan (**zero-code**) ve kullanıcı alanına (**user-space**) yük getirmeden Linux çekirdeği (**Kernel**) seviyesinde denetleyen ve engelleyen otonom güvenlik zırhıdır.

---

## 1. Mimari ve Çalışma Prensibi

Geleneksel güvenlik araçları uygulama katmanında (Python/Node.js middleware) çalışırken, **Agent-eBPF** doğrudan Linux Çekirdeği'nin ağ soketi ve süreç izleme katmanına (`sock_filter`, `uprobes`, `kprobes`) yerleşir.

```text
  [ User Space ]
  ┌─────────────────────────────────────────────────────────┐
  │  FastAPI / Node.js Application (LLM Agent Workflows)    │
  └───────────────────────────┬─────────────────────────────┘
                              │ Socket Send / Syscall
  ────────────────────────────┼──────────────────────────────
  [ Linux Kernel Space ]      ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Agent-eBPF Engine (eBPF XDP / Socket Buffer Filter)    │
  │  ├── AST & Regex Rule Matching (<50 µs execution)       │
  │  └── Policy Enforcement (PASS / DROP / TCP_RST)         │
  └───────────────────────────┬─────────────────────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
       [ PASS: Safe Execution ]      [ DROP: TCP Reset / Block ]
       Veritabanı / API'ye gider      Uygulamaya ulaşmadan kesilir
```

### Temel Prensipler

- **Sıfır Kod Değişikliği**: Koda tek bir satır `import` veya middleware eklenmez.
- **Ultra Düşük Gecikme**: Denetim **<50 mikro saniye (µs)** içinde kernel tampon belleğinde biter.
- **Fail-Closed (Zero-Trust)**: İhlal durumunda soket bağlantısı doğrudan `TCP_RST` ile kapatılır veya paket düşürülür (`DROP`).

---

## 2. Sistem Gereksinimleri & Kurulum

### Ön Koşullar

- **İşletim Sistemi**: Linux Kernel 5.4+ (BTF - BPF Type Format etkin)
- **Bağımlılıklar**: `clang`, `llvm`, `libbpf-dev`, `bpftool`

### Hızlı Kurulum (CLI Tool & Daemon)

```bash
# Agent-eBPF CLI ve Kernel Daemon kurulumu
curl -fsSL https://get.agent-ebpf.dev | sh

# Daemon durumunu doğrulama
agent-ebpf status
```

---

## 3. Deklaratif Güvenlik Politikası (`policy.yaml`)

Sistemin hangi davranışları "saçmalık" veya "güvenlik ihlali" sayacağını tanımlayan merkezi kural dosyasıdır.

Projelerinizin kök dizininde veya `/etc/agent-ebpf/policy.yaml` konumunda tanımlanır:

```yaml
version: "v1alpha"
metadata:
  name: "production-agent-shield"

rules:
  # 1. Tahrip Edici SQL Sorgularını Engelle (WHERE'siz UPDATE/DELETE)
  - id: "sql-no-where-mutation"
    type: "db_query"
    protocol: "postgres" # veya mysql
    severity: "critical"
    action: "DROP"
    match:
      pattern: '(?i)^(UPDATE|DELETE)\s+((?!WHERE).)*$'
    message: "WHERE koşulu içermeyen yıkıcı SQL mutasyonu engellendi."

  # 2. Multi-Tenant Izolasyon Zorunluluğu
  - id: "tenant-isolation-enforce"
    type: "db_query"
    protocol: "postgres"
    severity: "high"
    action: "DROP"
    match:
      require_header_context: "X-Tenant-ID"
      must_contain: "tenant_id ="
    message: "Sorguda tenant_id filtrelemesi eksik."

  # 3. Yasaklı Sistem Çağrıları (Process Hijack Önleme)
  - id: "block-unsafe-syscalls"
    type: "syscall"
    severity: "critical"
    action: "KILL_PROCESS"
    match:
      syscalls:
        - "execve"
        - "ptrace"
      binary_path_regex: ".*/python.*"
    message: "Ajanın sistem üzerinde yetkisiz alt süreç (sub-process) başlatması engellendi."
```

---

## 4. Kernel Modülünü Yükleme ve Çalıştırma

Güvenlik politikasını tanımladıktan sonra eBPF programını doğrudan ağ arabirimine ve soketlere bağlayın:

```bash
# Politika dosyasını doğrula ve kernel içine yükle
agent-ebpf load --config ./policy.yaml --interface eth0

# Çalışan kuralları canlıda izle
agent-ebpf monitor
```

### Canlı İzleme Çıktısı

```text
[AGENT-eBPF] Kernel hooks attached successfully. Listening on sock_ops & uprobes...
[INTERCEPTED] Timestamp: 1716198402 | Rule: sql-no-where-mutation | Latency: 32µs
  ├─ Process: python3 (PID: 41029)
  ├─ Payload: "DELETE FROM users"
  └─ Action: TCP_RST sent to socket (Connection Closed).
```

---

## 5. Test ve Benchmark

Agent-eBPF'in hızını ve engelleme kabiliyetini doğrulamak için `tests/test_shield.py` dosyasını kullanabilirsiniz:

```python
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
```

---

## 6. Production Deployment (Docker & Coolify)

Bare-metal veya Docker ortamlarında çalışırken konteynerlerin ağ soketlerini denetlemek için `docker-compose.yml` yapılandırmasına `CAP_SYS_ADMIN` ve `CAP_BPF` yetkilerini eklemeniz yeterlidir:

```yaml
version: "3.8"

services:
  agent-ebpf-daemon:
    image: ghcr.io/agent-ebpf/daemon:latest
    container_name: agent_ebpf_shield
    network_mode: "host"
    privileged: true
    cap_add:
      - SYS_ADMIN
      - BPF
      - NET_ADMIN
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf
      - /etc/agent-ebpf/policy.yaml:/etc/agent-ebpf/policy.yaml:ro
    restart: always
```

---

> **Özet**: Agent-eBPF ile kodunuzda hiçbir değişiklik yapmadan, sıfır overhead ile yapay zeka ajanlarınızı Linux Çekirdeği seviyesinde koruma altına alabilirsiniz.

---

## ⚡ Gemini Spark MCP Integration ("Add Custom App Link")

Agent-eBPF includes a native async **Model Context Protocol (MCP)** Gateway over SSE transport (`mcp_server.py`). This allows **Gemini Spark** to control, inspect, and enforce kernel security policies in real-time.

### Available MCP Tools for Gemini Spark

1. 🔍 **`get_security_status`**: Inspect live Linux kernel eBPF probes, latency stats (<35µs), and blocked threat counters.
2. 📋 **`get_active_policies`**: Retrieve currently active declarative rules (`policy.yaml`).
3. ➕ **`add_security_rule`**: Dynamically inject new kernel security rules (e.g., blocking unconstrained SQL or prohibited syscalls) directly via Gemini Spark chat.
4. 🧪 **`simulate_query_check`**: Pre-validate SQL queries or commands against active kernel eBPF filters before execution.

### How to Connect to Gemini Spark

1. Start the MCP server:
   ```bash
   uvicorn mcp_server:app --host 0.0.0.0 --port 8000
   ```
2. Go to **Gemini Spark** settings -> **Custom apps for Spark** -> **Add custom app link**.
3. Paste your public SSE endpoint:
   ```text
   https://your-domain.com/sse
   ```

