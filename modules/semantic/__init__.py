"""Couche sémantique : compréhension partagée et persistante de l'API.

Construite une fois depuis le HAR (+ OpenAPI), consommée par tous les moteurs
(investigator, matrice d'accès, BOLA, business flow) au lieu que chacun redevine
« à quoi correspond cette route ».
"""
from .api_model import APIModel, RouteInfo, route_is_sensitive

__all__ = ["APIModel", "RouteInfo", "route_is_sensitive"]
