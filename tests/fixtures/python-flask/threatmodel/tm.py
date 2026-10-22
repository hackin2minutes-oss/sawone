#!/usr/bin/env python3
"""Threat model of the self-test Flask app (OWASP pytm). Sawone draws its DFD, classifies the threats by
STRIDE and checks them against the scanners' findings; validate.yml asserts all of that end to end."""
from pytm import TM, Actor, Boundary, Classification, Data, Dataflow, Datastore, Process

tm = TM("selftest-flask")
tm.description = "Flask API with an in-memory SQLite store"
tm.isOrdered = True
tm.mergeResponses = True

internet = Boundary("Internet")
container = Boundary("Container")

user = Actor("API client")
user.inBoundary = internet

app = Process("Flask API")
app.inBoundary = container
app.sourceFiles = ["app.py"]
app.controls.sanitizesInput = False
app.controls.validatesInput = False
app.controls.implementsAuthenticationScheme = False

store = Datastore("SQLite")
store.inBoundary = container
store.isSQL = True

names = Data("User names", classification=Classification.RESTRICTED)

req = Dataflow(user, app, "API request")
req.protocol = "HTTP"
req.dstPort = 8080
req.data = names

query = Dataflow(app, store, "SQL query")
query.protocol = "SQLite"
query.data = names

resp = Dataflow(app, user, "API response")
resp.protocol = "HTTP"
resp.responseTo = req

MITIGATED = {}

if __name__ == "__main__":
    tm.process()
