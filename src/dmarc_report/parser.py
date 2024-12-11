"""Parse the XML file."""

from pathlib import Path
from typing import Union

import xmlschema

from dmarc_report.schema import Feedback as DMARCSchema

DMARC_XML_SCHEMA = "rua_modified.xsd"


def validate_and_parse_dmarc_report(xml_path: Union[str, Path]) -> DMARCSchema:
    """Validates a DMARC XML report against the schema and converts it to a Pydantic model.

    Args:
        xml_path: Path to the XML file to validate and parse

    Returns:
        Feedback: Pydantic model containing the parsed report data

    Raises:
        xmlschema.XMLSchemaValidationError: If the XML doesn't validate against the schema
        ValidationError: If the data doesn't match the Pydantic model constraints
    """
    # Create schema validator
    dmarc_xml_schema = Path(__file__).parent / DMARC_XML_SCHEMA

    # Create schema validator with relaxed namespace validation
    schema = xmlschema.XMLSchema(dmarc_xml_schema, validation="lax")

    # Define namespace maps for validation and parsing
    namespaces = {
        "": "http://dmarc.org/dmarc-xml/0.1",
        "ns": "http://dmarc.org/dmarc-xml/0.1",
    }

    # Validate first
    schema.validate(xml_path, namespaces=namespaces)

    # Convert to dict if validation passes
    xml_dict = schema.to_dict(xml_path, namespaces=namespaces, preserve_root=True)

    # Convert dict to Pydantic model
    return DMARCSchema.model_validate(xml_dict)
