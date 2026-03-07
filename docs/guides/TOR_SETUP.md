# Configuration TOR pour HAR-ZAP

Guide pour router le trafic de scan à travers le réseau TOR.

## Installation TOR

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install tor
sudo systemctl start tor
sudo systemctl enable tor
```

### macOS

```bash
brew install tor
brew services start tor
```

### Docker

```bash
docker run -d --name tor \
    -p 9050:9050 \
    -p 9051:9051 \
    dperson/torproxy
```

## Configuration HAR-ZAP

### Via config.yaml

```yaml
proxy_chain:
  enabled: true
  type: "socks5"
  host: "127.0.0.1"
  port: 9050

tor:
  control_port: 9051
  control_password: ""
  new_circuit_per_scan: false
```

### Via Variables d'Environnement

```bash
export HARZAP_TOR_ENABLED=true
export HARZAP_TOR_HOST=127.0.0.1
export HARZAP_TOR_PORT=9050
export HARZAP_TOR_CONTROL_PORT=9051
export HARZAP_TOR_CONTROL_PASSWORD=votre_password
```

### Via Interface Web

1. Ouvrir l'onglet **TOR Config**
2. Renseigner Host/Port
3. Cliquer **Appliquer la configuration**
4. Cliquer **Activer TOR dans ZAP**

## Port de Contrôle (Changement de Circuit)

Pour changer d'IP de sortie pendant les scans, configurez le port de contrôle TOR.

### Éditer /etc/tor/torrc

```
ControlPort 9051
HashedControlPassword 16:VOTRE_HASH_ICI
```

### Générer le Hash

```bash
tor --hash-password votre_mot_de_passe
```

### Redémarrer TOR

```bash
sudo systemctl restart tor
```

## Vérification

### Test Connexion SOCKS5

```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### Test via API HAR-ZAP

```bash
curl http://localhost:8000/api/v1/proxy/tor/status
```

### Via Interface Web

Dashboard > TOR Proxy > Vérifier connexion

## Intégration ZAP

Quand TOR est activé dans ZAP:
- Tout le trafic de scan passe par TOR
- Les requêtes spider/active scan sont anonymisées
- L'IP cible ne voit que l'IP de sortie TOR

### Activer

```bash
curl -X POST http://localhost:8000/api/v1/proxy/tor/enable
```

### Désactiver

```bash
curl -X POST http://localhost:8000/api/v1/proxy/tor/disable
```

### Nouveau Circuit

```bash
curl -X POST http://localhost:8000/api/v1/proxy/tor/new-circuit
```

## Troubleshooting

### TOR non connecté

1. Vérifier que TOR tourne: `systemctl status tor`
2. Vérifier le port: `netstat -tlnp | grep 9050`
3. Tester manuellement: `curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip`

### Nouveau circuit échoue

1. Vérifier le port de contrôle: `netstat -tlnp | grep 9051`
2. Vérifier le password dans torrc
3. Tester: `echo -e 'AUTHENTICATE "password"\nSIGNAL NEWNYM\nQUIT' | nc 127.0.0.1 9051`

### Lenteur des scans

TOR ajoute de la latence. Options:
- Réduire le nombre de threads ZAP
- Utiliser `new_circuit_per_scan: true` pour isoler les scans
- Considérer un bridge TOR privé pour plus de débit
