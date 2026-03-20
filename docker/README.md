# HAR.ZAP Docker Observability Stack

Stack Docker pour visualiser les logs ZAP dans Grafana (Loki) ou Kibana (ELK).

## Quick Start

### Option 1: Loki + Grafana (recommandé, léger)

```bash
cd docker
docker compose -f docker-compose.observability.yml --profile loki up -d
```

- **Grafana**: http://localhost:3000 (admin / harzap2024)
- **Loki**: http://localhost:3100
- **ZAP**: http://localhost:8080

### Option 2: ELK Stack (full-featured)

```bash
cd docker
LOG_BACKEND=elasticsearch docker compose -f docker-compose.observability.yml --profile elk up -d
```

- **Kibana**: http://localhost:5601
- **Elasticsearch**: http://localhost:9200
- **ZAP**: http://localhost:8080

### Option 3: Les deux (dev/comparison)

```bash
cd docker
docker compose -f docker-compose.observability.yml --profile elk --profile loki up -d
```

## Architecture

```
                                                  ▼
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_BACKEND` | `loki` | Backend: `loki` ou `elasticsearch` |
| `ZAP_URL` | `http://zap:8080` | URL API ZAP |
| `LOKI_URL` | `http://loki:3100` | URL Loki |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | URL Elasticsearch |
| `POLL_INTERVAL` | `5` | Intervalle polling (secondes) |

## Dashboards pré-configurés

### Grafana (Loki)

- **High/Medium Risk Alerts** - Compteurs temps réel
- **Alerts by Type** - Pie chart par catégorie
- **Security Alerts Stream** - Logs live
- **Request Rate** - Graphique débit
- **Recent Vulnerabilities** - Table des dernières vulns

### Kibana (ELK)

Créer un Data View sur `zap-*` puis:
- Discover pour recherche full-text
- Dashboard personnalisés
- Alerting sur patterns

## Données indexées

### Alerts (`zap-alerts-*`)

```json
{
  "@timestamp": "2024-01-15T10:30:00Z",
  "type": "alert",
  "name": "Mass Assignment",
  "risk": "HIGH",
  "risk_score": 3,
  "url": "https://api.example.com/users",
  "param": "isAdmin",
  "attack": "isAdmin=true",
  "evidence": "...",
  "cweid": 915
}
```

### Requests (`zap-requests-*`)

```json
{
  "@timestamp": "2024-01-15T10:30:00Z",
  "type": "request",
  "method": "POST",
  "url": "/api/users",
  "status_code": 200,
  "response_length": 1234
}
```

## Commandes utiles

```bash
# Voir les logs du shipper
docker logs -f harzap-shipper

# Redémarrer le shipper
docker restart harzap-shipper

# Vérifier Loki
curl http://localhost:3100/ready

# Vérifier Elasticsearch
curl http://localhost:9200/_cluster/health

# Arrêter tout
docker compose -f docker-compose.observability.yml --profile loki down

# Nettoyer volumes (ATTENTION: perte de données)
docker compose -f docker-compose.observability.yml --profile loki down -v
```

## Troubleshooting

### Shipper ne démarre pas

1. Vérifier que ZAP est accessible: `curl http://localhost:8080/JSON/core/view/version/`
2. Vérifier les logs: `docker logs harzap-shipper`

### Pas de données dans Grafana

1. Vérifier Loki: `curl http://localhost:3100/ready`
2. Vérifier que des requêtes passent par ZAP
3. Attendre quelques secondes (poll interval)

### Elasticsearch out of memory

Augmenter la RAM dans docker-compose:
```yaml
environment:
  - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
```
