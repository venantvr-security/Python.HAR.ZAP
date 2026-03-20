# 🎭 Mass Assignment / Privilege Escalation

## Qu'est-ce que c'est ?

Le **Mass Assignment** exploite le fait que les applications acceptent aveuglément tous les paramètres envoyés, y compris ceux qui ne devraient pas être modifiables par
l'utilisateur.

## Logique de l'attaque

1. **Identification** : Trouver les endpoints POST/PUT/PATCH qui acceptent du JSON
2. **Injection** : Ajouter des paramètres dangereux au payload légitime :
    - `"is_admin": true`
    - `"role": "superadmin"`
    - `"balance": 999999`
    - `"permissions": ["*"]`
3. **Analyse** : Vérifier si le serveur accepte et applique ces paramètres
4. **Confirmation** : Tester si les privilèges ont réellement changé

## Pourquoi c'est dangereux ?

Un attaquant peut :

- S'octroyer des privilèges administrateur
- Modifier son solde/crédits dans une application
- Bypasser des restrictions métier
- Accéder à des fonctionnalités premium

## Exemple de vulnérabilité

```json
Requête légitime:
POST /api/users/profile
{
"name": "John",
"email": "john@example.com"
}

Requête avec mass assignment: POST /api/users/profile
{
"name": "John",
"email": "john@example.com",
"is_admin": true,
"credits": 999999
}

Si accepté ← VULNÉRABLE !
```

## Cas réels célèbres

- **GitHub (2012)** : Un utilisateur a pu se donner accès admin aux repos via mass assignment
- **Zendesk** : Escalade de privilèges via injection de paramètres

## Remédiation

- Utiliser des **whitelists** de paramètres autorisés
- Ne jamais binder automatiquement tous les paramètres HTTP
- Séparer les DTOs public/admin
- Valider et filtrer TOUS les inputs côté serveur
- Frameworks : utiliser `@JsonIgnore`, `readonly`, etc.
