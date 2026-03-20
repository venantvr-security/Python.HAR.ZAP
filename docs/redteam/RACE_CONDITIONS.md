# ⚡ Race Condition Detection

## Qu'est-ce que c'est ?

Une **Race Condition** se produit quand plusieurs requêtes simultanées exploitent un délai dans les vérifications serveur, permettant des actions qui devraient être
impossibles.

## Logique de l'attaque

1. **Identification** : Trouver des endpoints critiques :
    - Transferts d'argent
    - Achats/commandes
    - Créations de ressources limitées
    - Opérations avec quotas
2. **Burst** : Envoyer 50-100 requêtes identiques SIMULTANÉMENT
3. **Analyse** : Vérifier si :
    - Toutes les requêtes ont réussi (codes 2xx)
    - Les réponses sont incohérentes
    - Des variations de taille apparaissent
4. **Exploitation** : Confirmer que la logique métier a été bypassée

## Pourquoi c'est critique ?

Un attaquant peut :

- Dépenser plus d'argent qu'il n'en possède
- Utiliser un coupon promo plusieurs fois
- Acheter plus d'items qu'en stock
- Bypasser les rate limits
- Créer plusieurs comptes avec le même email

## Exemple de vulnérabilité

```
Solde initial: 100€

Envoyer 10x simultanément:
POST /api/transfer
{ "amount": 100, "to": "attacker" }

Sans protection race condition:
✓ Transfert 1: 100€ (solde: 0€)
✓ Transfert 2: 100€ (solde: -100€) ← PROBLÈME!
✓ Transfert 3: 100€ (solde: -200€)
...

Résultat: 1000€ transférés avec seulement 100€ en solde
```

## Comment ça se produit ?

```python
# Code VULNÉRABLE
def transfer(user, amount):
    balance = get_balance(user)  # ← Race window
    if balance >= amount:  # ← Race window
        deduct_balance(user, amount)
        send_money(amount)
        return "OK"
    return "Insufficient funds"

# 2 requêtes simultanées lisent balance=100 avant que
# l'une d'elles ne le mette à jour → double transfert!
```

## Cas réels célèbres

- **Starbucks (2018)** : Race condition permettait de recharger une carte cadeau plusieurs fois pour le prix d'une
- **Crypto exchanges** : Double-spending via race conditions
- **E-commerce** : Achats d'articles en rupture de stock

## Détection technique

L'outil envoie des requêtes concurrentes et analyse :

- **Status codes** : Trop de 200 OK
- **Response lengths** : Variations anormales
- **Timing** : Patterns suspects
- **Error messages** : Inconsistances

## Remédiation

**Niveau Database:**

```sql
-- Utiliser des transactions avec locks
BEGIN TRANSACTION;
SELECT balance FROM accounts WHERE id = ? FOR UPDATE;
-- Le FOR UPDATE lock la ligne
UPDATE accounts SET balance = balance - ? WHERE id = ?;
COMMIT;
```

**Niveau Application:**

- **Locks distribués** (Redis, Memcached)
- **Idempotency keys** : Chaque requête a un ID unique
- **Optimistic locking** : Vérifier la version avant update
- **Queues** : Serialiser les opérations critiques
- **Rate limiting strict** par utilisateur

**Tests:**

- Load testing avec concurrence
- Tools comme `ab`, `wrk`, `locust`
- Monitoring des anomalies métier
