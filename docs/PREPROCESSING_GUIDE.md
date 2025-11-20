# Guide de Préprocessing HAR

## Vue d'ensemble

Le **HARPreprocessor** est le point d'entrée unique pour traiter un fichier HAR. Il extrait **tout** en un seul passage et génère un fichier JSON unifié qui sera consommé
par tous les autres modules.

## Philosophie

**Un HAR → Un fichier preprocessed.json → Tous les modules**

Plus besoin de parser le HAR plusieurs fois ou d'avoir des formats incompatibles entre modules.

## Workflow Standard

```python
from modules.har_preprocessor import HARPreprocessor

# 1. Charger et préprocesser
preprocessor = HARPreprocessor(har_path='capture.har')

# 2. (Optionnel) Appliquer des filtres
preprocessor.set_filters(
    methods=['POST', 'PUT'],
    domains=['api.example.com'],
    exclude_static=True
)

# 3. Sauvegarder le fichier unifié
preprocessor.save('preprocessed.json')

# 4. Utiliser dans les autres modules
# Tous les modules acceptent maintenant preprocessed.json
```

## Structure du fichier de sortie

```json
{
  "metadata": {
    "source": "HAR file",
    "processed_at": "2025-11-20T...",
    "filters_applied": {
      ...
    },
    "total_entries": 156
  },
  "endpoints": [
    {
      "id": 0,
      "url": "https://api.example.com/users/123",
      "endpoint": "/users/{id}",
      "method": "GET",
      "status_code": 200,
      "has_auth": true,
      "auth_headers": {
        "Authorization": "Bearer ..."
      }
    }
  ],
  "querystrings": {
    "/api/search": [
      {
        "parameter": "q",
        "value": "test",
        "full_query": "q=test&limit=10"
      }
    ]
  },
  "payloads": {
    "/api/users": [
      {
        "direction": "request",
        "method": "POST",
        "payload": {
          "name": "John",
          "email": "john@example.com"
        },
        "size": 45
      }
    ]
  },
  "dictionaries": {
    "keys": {
      "user_id": {
        "type": "int",
        "endpoints": [
          "/api/users"
        ],
        "examples": [
          123,
          456,
          789
        ]
      }
    },
    "values": {
      "role": [
        "admin",
        "user",
        "guest"
      ]
    },
    "parameters": {
      "q": [
        "test",
        "search",
        "query"
      ]
    },
    "headers": {
      "Authorization": [
        "Bearer token1",
        "Bearer token2"
      ]
    }
  },
  "statistics": {
    "total_endpoints": 45,
    "unique_endpoint_patterns": 12,
    "methods": {
      "GET": 30,
      "POST": 15
    },
    "total_unique_keys": 67
  }
}
```

## Filtres Disponibles

### Filtres de méthode HTTP

```python
preprocessor.set_filters(
    methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
)
```

### Filtres de domaine

```python
# Inclure seulement certains domaines
preprocessor.set_filters(
    domains=['api.example.com', 'auth.example.com']
)

# Exclure certains domaines
preprocessor.set_filters(
    exclude_domains=['cdn.example.com', 'analytics.com']
)
```

### Filtres de status code

```python
preprocessor.set_filters(
    status_codes=[200, 201, 204]  # Seulement les succès
)
```

### Filtres de content-type

```python
preprocessor.set_filters(
    content_types=['application/json']  # Seulement JSON
)
```

### Filtres de taille de réponse

```python
preprocessor.set_filters(
    min_response_size=100,  # Au moins 100 bytes
    max_response_size=1000000  # Max 1MB
)
```

### Exclure les ressources statiques

```python
preprocessor.set_filters(
    exclude_static=True  # Exclut .js, .css, images, fonts
)
```

## Cas d'usage

### 1. Analyse API pure (pas de frontend)

```python
preprocessor = HARPreprocessor('capture.har')
preprocessor.set_filters(
    methods=['POST', 'PUT', 'PATCH', 'DELETE'],
    content_types=['application/json'],
    exclude_static=True
)
preprocessor.save('api_only.json')
```

### 2. Focus sur un domaine spécifique

```python
preprocessor = HARPreprocessor('capture.har')
preprocessor.set_filters(
    domains=['api.target.com'],
    exclude_domains=['cdn.target.com']
)
preprocessor.save('target_api.json')
```

### 3. Debugging (tout garder)

```python
preprocessor = HARPreprocessor('capture.har')
preprocessor.set_filters(
    exclude_static=False  # Garder même les .js/.css
)
preprocessor.save('full_debug.json')
```

### 4. Extraction granulaire (fichiers séparés)

```python
preprocessor = HARPreprocessor('capture.har')
preprocessor.save_extracts('output/extracts')

# Génère:
# - output/extracts/endpoints.json
# - output/extracts/querystrings.json
# - output/extracts/payloads.json
# - output/extracts/dictionaries.json
# - output/extracts/statistics.json
# - output/extracts/metadata.json
```

## Intégration avec les autres modules

### Avec PayloadAnalyzer

```python
import json
from modules.payload_analyzer import PayloadAnalyzer

# Charger le fichier preprocessed
with open('preprocessed.json', 'r') as f:
    data = json.load(f)

# Utiliser directement les payloads
for endpoint, payloads in data['payloads'].items():
    for payload_data in payloads:
        # Analyser
        pass
```

### Avec TokenExtractor

```python
from modules.token_extractor import TokenExtractor

# Les dictionaries sont déjà extraits!
with open('preprocessed.json', 'r') as f:
    data = json.load(f)

# Utiliser directement
dictionaries = data['dictionaries']
# dictionaries['keys'] contient tous les champs JSON
# dictionaries['values'] contient toutes les valeurs observées
```

### Avec RedTeamOrchestrator

```python
from modules.redteam_attacks import RedTeamOrchestrator

with open('preprocessed.json', 'r') as f:
    preprocessed = json.load(f)

# Cibler les endpoints avec auth
auth_endpoints = [
    e for e in preprocessed['endpoints']
    if e['has_auth']
]

# Lancer attaques sur ces endpoints
for endpoint in auth_endpoints:
    # Unauth replay attack
    pass
```

## Commandes CLI

### Préprocessing basique

```bash
python examples/preprocess_har.py capture.har
```

### Avec filtres custom (script)

```python
#!/usr/bin/env python3
from modules.har_preprocessor import HARPreprocessor
import sys

preprocessor = HARPreprocessor(sys.argv[1])
preprocessor.set_filters(
    methods=['POST'],
    domains=['api.prod.com'],
    status_codes=[200, 201]
)
preprocessor.save('output/prod_api.json')
preprocessor.print_summary()
```

## Performances

Le preprocessing est fait en **un seul passage** sur le HAR:

- **Parsing**: 1 seule fois
- **Filtrage**: appliqué en temps réel
- **Extraction**: tout en parallèle (endpoints, payloads, dicts)

**Benchmark** (HAR de 500 requêtes):

- Temps de processing: ~2-3 secondes
- Fichier preprocessed: ~500KB (compressé avec structure)
- Réduction de parsing: 10x (plus besoin de parser dans chaque module)

## Sauvegarde locale & Versioning

```python
# Sauvegarder avec timestamp
from datetime import datetime

timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
output_path = f'preprocessed_{timestamp}.json'

preprocessor = HARPreprocessor('capture.har')
preprocessor.save(output_path)

# Comparer deux versions
import json

with open('preprocessed_v1.json') as f:
    v1 = json.load(f)

with open('preprocessed_v2.json') as f:
    v2 = json.load(f)

# Diff endpoints
new_endpoints = set(
    e['endpoint'] for e in v2['endpoints']
) - set(
    e['endpoint'] for e in v1['endpoints']
)

print(f"Nouveaux endpoints: {new_endpoints}")
```

## Troubleshooting

### HAR trop gros (> 100MB)

```python
# Filtrer agressivement
preprocessor.set_filters(
    exclude_static=True,
    methods=['POST', 'PUT'],
    min_response_size=50,
    max_response_size=100000
)
```

### Trop de données extraites

```python
# Limiter aux endpoints principaux seulement
preprocessor.set_filters(
    domains=['api.main.com'],  # Domaine principal uniquement
    exclude_domains=['*.cdn.com', '*.analytics.com']
)
```

### Debugging extraction

```python
# Voir le résumé avant sauvegarde
preprocessor.print_summary()

# Vérifier les filtres appliqués
result = preprocessor.process()
print(result.metadata['filters_applied'])
```

## Best Practices

1. **Toujours filtrer les ressources statiques** en production
2. **Sauvegarder le preprocessed.json** pour éviter de re-parser
3. **Versionner** les fichiers preprocessed si l'API évolue
4. **Utiliser des filtres stricts** pour les gros HARs
5. **Vérifier les statistics** avant d'attaquer
6. **Un fichier preprocessed par environnement** (dev/staging/prod)

## Exemples complets

Voir `examples/preprocess_har.py` pour des exemples fonctionnels.
