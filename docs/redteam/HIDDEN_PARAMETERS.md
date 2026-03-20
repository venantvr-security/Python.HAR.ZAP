# 🔍 Hidden Parameter Discovery

## Qu'est-ce que c'est ?

La **découverte de paramètres cachés** consiste à tester des paramètres non documentés (query params, POST params) qui peuvent débloquer des fonctionnalités cachées ou
des modes debug.

## Logique de l'attaque

1. **Baseline** : Faire une requête normale et enregistrer la réponse
2. **Fuzzing** : Ajouter des paramètres suspects courants :
    - `?debug=true`
    - `?admin=1`
    - `?test=1`
    - `?trace=true`
    - `?verbose=1`
3. **Comparaison** : Comparer les réponses avec la baseline
4. **Détection** : Si la réponse change (taille, contenu, headers), un paramètre caché existe

## Pourquoi c'est dangereux ?

Les paramètres cachés peuvent :

- Activer des modes debug qui exposent des infos sensibles
- Bypasser des validations
- Exposer des endpoints d'administration
- Révéler la stack technique et des vulnérabilités

## Exemple de vulnérabilité

```
Requête normale:
GET /api/data
Réponse: {"result": [...]}

Requête avec paramètre caché:
GET /api/data?debug=true
Réponse: {
  "result": [...],
  "sql_query": "SELECT * FROM users WHERE...",
  "execution_time": "0.5ms",
  "server_info": {...}
}
← VULNÉRABLE ! Fuite d'informations sensibles
```

## Paramètres courants testés

**Debug/Test:**

- `debug`, `test`, `dev`, `trace`, `verbose`
- `show_errors`, `stack_trace`

**Admin:**

- `admin`, `administrator`, `root`, `superuser`
- `is_admin`, `role`

**Features:**

- `feature_flag`, `experimental`, `beta`
- `override`, `bypass`

## Cas réels

- **Twitter (2020)** : Paramètre `?admin=1` exposait un panel interne
- Nombreuses APIs avec `?debug=1` exposant des stack traces

## Remédiation

- Supprimer TOUS les paramètres debug en production
- Feature flags doivent être côté serveur, pas dans les URLs
- Ne jamais se fier aux paramètres pour les contrôles d'accès
- Logs et monitoring pour détecter l'énumération de paramètres
- WAF rules pour bloquer les patterns suspects
