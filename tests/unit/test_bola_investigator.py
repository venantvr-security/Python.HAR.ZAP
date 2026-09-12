"""Tests du BOLA Investigator (confirmation croisée + adjudication IA simulée)."""
import json

from modules.llm.bola_investigator import BolaInvestigator, Session


class OwnedServer:
    """Objets appartenant à un propriétaire ; le champ 'owner' l'expose.
    L'accès n'est PAS contrôlé (BOLA) : quiconque authentifié lit tout objet ;
    anon est refusé."""

    def __init__(self, objects):
        self.objects = objects  # url -> {owner, secret}

    def send(self, method, url, headers=None):
        authed = bool((headers or {}).get("Authorization"))
        if url not in self.objects:
            return {"status": 404, "body": "{}"}
        if not authed:
            return {"status": 401, "body": "{}"}
        return {"status": 200, "body": json.dumps(self.objects[url])}


BASE = "https://api.x/books/v1"
OBJECTS = {
    f"{BASE}/b_admin": {"owner": "admin", "secret": "s1"},
    f"{BASE}/b_name1": {"owner": "name1", "secret": "s2"},
}
SESSIONS = [
    Session("anon", {}, identity=None),
    Session("name1", {"Authorization": "N1"}, identity="name1"),
    Session("admin", {"Authorization": "A"}, identity="admin"),
]


class TestProbe:
    def test_confirms_cross_owner_read(self):
        srv = OwnedServer(OBJECTS)
        inv = BolaInvestigator(srv.send)
        f = inv.probe(list(OBJECTS), SESSIONS, ownership_field="owner")
        # name1 lit l'objet d'admin -> BOLA ; admin lit celui de name1 -> BOLA.
        pairs = {(x.attacker, x.owner) for x in f if x.confirmed}
        assert ("name1", "admin") in pairs
        assert ("admin", "name1") in pairs

    def test_owner_reading_own_is_not_flagged(self):
        srv = OwnedServer(OBJECTS)
        inv = BolaInvestigator(srv.send)
        f = inv.probe(list(OBJECTS), SESSIONS, ownership_field="owner")
        assert not any(x.attacker == "admin" and x.owner == "admin" for x in f)
        assert not any(x.attacker == "name1" and x.owner == "name1" for x in f)

    def test_anon_denied_no_finding(self):
        srv = OwnedServer(OBJECTS)
        inv = BolaInvestigator(srv.send)
        f = inv.probe(list(OBJECTS), SESSIONS, ownership_field="owner")
        assert not any(x.attacker == "anon" for x in f)  # anon reçoit 401

    def test_proper_enforcement_no_findings(self):
        # Serveur qui contrôle : chacun ne lit que son objet.
        class Strict:
            def send(self, method, url, headers=None):
                tok = (headers or {}).get("Authorization")
                who = {"N1": "name1", "A": "admin"}.get(tok)
                obj = OBJECTS.get(url)
                if not obj:
                    return {"status": 404, "body": "{}"}
                if who and obj["owner"] == who:
                    return {"status": 200, "body": json.dumps(obj)}
                return {"status": 403, "body": "{}"}
        f = BolaInvestigator(Strict().send).probe(
            list(OBJECTS), SESSIONS, ownership_field="owner")
        assert f == []


class TestEnumeration:
    def test_object_urls_from_list(self):
        listing = {"Books": [{"book_title": "b_admin", "user": "admin"},
                             {"book_title": "b_name1", "user": "name1"}]}

        def send(method, url, headers=None):
            return {"status": 200, "body": json.dumps(listing)}
        inv = BolaInvestigator(send)
        urls = inv.object_urls_from_list(f"{BASE}", BASE, "book_title")
        assert f"{BASE}/b_admin" in urls and f"{BASE}/b_name1" in urls


class TestLLMAdjudication:
    def test_opaque_object_uses_llm(self):
        # Pas de champ de propriété : deux sessions distinctes reçoivent le même
        # corps opaque -> l'IA tranche que c'est un BOLA.
        body = json.dumps({"data": "secret-blob"})

        class Server:
            def send(self, method, url, headers=None):
                return {"status": 200, "body": body} if (headers or {}).get("Authorization") \
                    else {"status": 401, "body": "{}"}

        class Client:
            class _R:
                def __init__(self, c): self.content = c

            def complete(self, prompt, system=None):
                return self._R(json.dumps({"bola": True, "reason": "same private blob"}))

        inv = BolaInvestigator(Server().send, client=Client())
        f = inv.probe([f"{BASE}/opaque"],
                      [Session("name1", {"Authorization": "N1"}, "name1"),
                       Session("name2", {"Authorization": "N2"}, "name2")],
                      ownership_field=None)
        assert any(x.confirmed and x.source == "llm" for x in f)
