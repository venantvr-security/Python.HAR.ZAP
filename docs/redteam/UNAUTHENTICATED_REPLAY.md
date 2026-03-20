# 🔓 Unauthenticated Replay Attack

## Qu'est-ce que c'est ?

L'attaque **Unauthenticated Replay** consiste à rejouer des requêtes initialement authentifiées mais en supprimant tous les tokens d'authentification (cookies, headers
Authorization, etc.).

Cette vulnérabilité révèle un **broken access control** critique : l'application ne vérifie pas l'authentification côté serveur et se fie uniquement aux données client.

## Logique de l'attaque (Détaillée)

### Phase 1: Identification des requêtes authentifiées

- Scanner le HAR pour identifier les patterns d'authentification:
    - Headers `Authorization: Bearer <token>`
    - Headers `Authorization: Basic <base64>`
    - Cookies `session`, `auth_token`, `jwt`, `PHPSESSID`, etc.
    - Headers custom `X-Auth-Token`, `X-API-Key`, etc.
- Classer par criticité (GET vs POST/PUT/DELETE/PATCH)
- Identifier les endpoints sensibles (profil, admin, données utilisateur)

### Phase 2: Préparation de l'attaque

```python
# Requête originale
GET / api / user / profile / 12345
Authorization: Bearer
eyJhbGc...
Cookie: session = abc123

# Transformation pour l'attaque
GET / api / user / profile / 12345
# TOUS les headers d'auth retirés
```

### Phase 3: Exécution du replay

- Rejouer la requête **sans authentification**
- Capturer le status code ET le contenu de la réponse
- Mesurer le temps de réponse (peut révéler des checks manquants)

### Phase 4: Analyse différentielle

Comparer la réponse sans auth vs avec auth:

**Vulnérable si:**

- Status code: `200` au lieu de `401/403`
- Contenu identique ou très similaire
- Headers identiques (pas de `WWW-Authenticate`)
- Taille de réponse proche

**Faux positifs possibles:**

- Endpoint réellement public mais présence d'auth pour tracking
- Rate limiting qui répond 200 avec message d'erreur
- Redirections 302/307 vers login

## Pourquoi c'est critique ?

Cette vulnérabilité signifie que :

- Des endpoints sensibles sont accessibles sans authentification
- Un attaquant peut accéder à des données privées sans compte
- La logique d'autorisation est absente ou mal implémentée côté serveur

## Exemple de vulnérabilité

```
Requête originale:
GET /api/user/profile
Authorization: Bearer eyJhbGc...
Cookie: session=abc123

Requête rejouée (sans auth):
GET /api/user/profile
(pas de headers d'auth)

Réponse: 200 OK ← VULNÉRABLE !
Devrait être: 401 Unauthorized
```

## Détection technique avancée

### Méthodes de comparaison

```python
# Similarité de contenu (Levenshtein distance)
from difflib import SequenceMatcher

similarity = SequenceMatcher(None, auth_response, noauth_response).ratio()
# > 0.7 = suspect, > 0.9 = très probable

# Analyse structurelle JSON
if both_json:
    auth_keys = set(auth_json.keys())
    noauth_keys = set(noauth_json.keys())
    if auth_keys == noauth_keys:  # Structure identique
# VULNERABLE!
```

### Patterns de réponse vulnérables

```json
// Réponse sans auth qui devrait être 401
{
  "user_id": 12345,
  "email": "victim@example.com",
  "role": "user",
  "data": {
    ...
  }
}

// Au lieu de:
{
  "error": "Unauthorized",
  "message": "Authentication required"
}
```

## Impact réel & Exploitation

### Scénario d'exploitation typique

1. Attaquant capture HAR d'un utilisateur légitime (phishing, MitM, XSS)
2. Identifie endpoint `/api/user/orders` avec auth
3. Teste sans auth → **200 OK** avec données
4. Énumère les IDs: `/api/user/orders?user_id=1`, `2`, `3`...
5. **Accède aux commandes de tous les utilisateurs**

### Données exposées fréquentes

- Profils utilisateur complets (email, phone, adresse)
- Historique de commandes/transactions
- Documents privés (factures, contrats)
- Logs d'activité
- Données médicales/financières sensibles

### Chaining avec d'autres vulnérabilités

- **IDOR + Unauth Replay** = Accès à toutes les données de tous les users
- **CSRF + Unauth Replay** = Actions critiques sans authentification
- **Rate limit bypass** via rotation d'IPs

## Remédiation (Framework-specific)

### Node.js/Express

```javascript
// Middleware d'authentification OBLIGATOIRE
const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });

    try {
        const decoded = jwt.verify(token, SECRET);
        req.user = decoded;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Appliquer sur TOUTES les routes sensibles
app.get('/api/user/profile', requireAuth, getUserProfile);
app.post('/api/orders', requireAuth, createOrder);
```

### Python/Flask

```python
from functools import wraps
from flask import request, jsonify


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token'}), 401

        try:
            # Vérifier le token
            user = verify_token(token)
            request.current_user = user
        except:
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)

    return decorated


@app.route('/api/user/profile')
@require_auth
def get_profile():
    return jsonify(request.current_user)
```

### Django REST Framework

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes


@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Force l'authentification
def user_profile(request):
    return Response(request.user.data)
```

### Checklist de sécurité

- [ ] Middleware d'auth sur TOUTES les routes sensibles
- [ ] Tests automatisés vérifiant 401/403 sans auth
- [ ] Pas de logique métier exécutée avant check auth
- [ ] Logs détaillés des tentatives d'accès non auth
- [ ] WAF rules détectant les tentatives de bypass
- [ ] Rate limiting strict sur endpoints critiques
- [ ] Fail-secure: en cas d'erreur → deny access

## Références & Standards

**OWASP Top 10:**

- A01:2021 – Broken Access Control (rank #1)

**CWE:**

- CWE-287: Improper Authentication
- CWE-306: Missing Authentication for Critical Function

**Conformité:**

- PCI-DSS 6.5.10: Broken Authentication and Session Management
- GDPR Art. 32: Security of processing
