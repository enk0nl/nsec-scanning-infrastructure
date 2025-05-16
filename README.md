# 🛡️ nsec-scanning-infrastructure

This is a modular container-based system designed to scan DNS zones, with special focus on NSEC and NSEC3. It enables automated analysis of DNSSEC-protected zones using multiple parallel workers. It also provides a disclaimer web interface for transparency and logs all findings in a PostgreSQL database.

---

## 🧩 Overview

This project uses Docker Compose to orchestrate:

- **Web (`nginx`)**  
  An unprivileged, hardened NGINX server that serves a disclaimer to scanned parties.

- **DNS (`coredns`)**  
  A CoreDNS server for local caching and forwarding to public resolvers `8.8.8.8` and `8.8.4.4`.

- **DB (`postgres`)**  
  A PostgreSQL database that stores scan results, logs, and metadata.

- **Scanning workers (`nsec3map`)**  
  A scalable set of workers (default: 10) that analyze NSEC/NSEC3 DNS zones.

---

## 🚀 Getting started

### Prerequisites

- Docker and Docker Compose

### 1. Clone my fork of nsec3map into /usr/src

```bash
cd /usr/src
git clone https://github.com/enk0nl/nsec3map.git
```

### 2. Review the configuration files

- **Secrets**:
  You can configure the database credentials in the `db_user.txt` and `db_password.txt` files that exist in the `./conf` directory.

- **DNS forwarding and rate limiting**:
  CoreDNS will cache DNS queries and forward upstream to public resolvers. This is configured in `./conf/Corefile`.

- **Disclaimer page**:
  The disclaimer for external systems being scanned is served from the `./disclaimer` directory. Edit the HTML file as needed.

- **Database logging**:
  By default, Postgres is configured to log all queries in accordance with the _CIS PostgreSQL 17 Benchmark v1.0.0_. You can change this behavior in `./conf/postgresql.conf`.

- **Scaling NSEC3map workers**:
  Adjust the scale value under `nsec3map` in `./compose.yaml` to increase or reduce the number of parallel DNSSEC mappers.

### 3. Build the containers and bring up the infrastructure

```bash
cd ~/nsec-scanning-infrastructure
docker compose up --build
```

---

## 🌐 Network architecture

All services communicate over a custom Docker network (`dnsscanner`) with assigned IPs for core services.

| Service    | IP Address      | Exposed ports                                                                               |
| ---------- | --------------- | ------------------------------------------------------------------------------------------- |
| nginx      | dynamic         | 80 tcp, listening on all interfaces, mapped to 8080 in the container                        |
| CoreDNS    | `192.168.53.53` | 53 tcp/udp in the `dnsscanner` network, 5533 udp locally, mapped to 53 udp in the container |
| PostgreSQL | `192.168.53.54` | 5432 tcp in the `dnsscanner` network, 5432 tcp locally                                      |
| nsec3map   | dynamic         | None                                                                                        |

---

## 🧪 Scanning coordinator
The scanning coordinator is currently not publicly available. If you'd like access to the repository, feel free to reach out to me directly.
