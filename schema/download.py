"""Downlaod the DMARC XML schema."""

import xmlschema

schema = xmlschema.XMLSchema("https://dmarc.org/dmarc-xml/0.1/rua.xsd")
schema.export(target="schema/download", save_remote=True)
