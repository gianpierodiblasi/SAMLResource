package com.thingworx.extension.custom.saml;

import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;
import com.thingworx.data.util.InfoTableInstanceFactory;
import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinition;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinitions;
import com.thingworx.metadata.annotations.ThingworxDataShapeDefinition;
import com.thingworx.metadata.annotations.ThingworxFieldDefinition;
import com.thingworx.metadata.annotations.ThingworxServiceDefinition;
import com.thingworx.metadata.annotations.ThingworxServiceParameter;
import com.thingworx.metadata.annotations.ThingworxServiceResult;
import com.thingworx.resources.Resource;
import com.thingworx.types.ConfigurationTable;
import com.thingworx.types.InfoTable;
import com.thingworx.types.collections.ValueCollection;
import com.thingworx.types.primitives.StringPrimitive;
import org.slf4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

@ThingworxConfigurationTableDefinitions(tables = {
  @ThingworxConfigurationTableDefinition(name = "X509CertificateParameters", description = "", isMultiRow = false, ordinal = 0, dataShape = @ThingworxDataShapeDefinition(fields = {
    @ThingworxFieldDefinition(name = "X509Certificate", description = "The X509 Certificate", baseType = "STRING", ordinal = 0, aspects = {"isRequired:true"})}))})
public class SAMLResource extends Resource {

  private final static Logger SCRIPT_LOGGER = LogUtilities.getInstance().getScriptLogger(SAMLResource.class);
  private static final long serialVersionUID = 1L;

  @ThingworxServiceDefinition(name = "validateAssertion", description = "", category = "", isAllowOverride = false, aspects = {"isAsync:false"})
  @ThingworxServiceResult(name = "result", description = "", baseType = "BOOLEAN", aspects = {})
  public Boolean validateAssertion(
          @ThingworxServiceParameter(name = "xml", description = "The XML Document", baseType = "XML", aspects = {"isRequired:true"}) Document xml) throws Exception {
    SCRIPT_LOGGER.debug("SAMLResource - validateAssertion -> Start");

    boolean result = false;

    if (Util.validateXML(xml, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
      ConfigurationTable configTable = this.getConfigurationTable("X509CertificateParameters");
      ValueCollection collection = configTable.getFirstRow();
      String certString = collection.getStringValue("X509Certificate");

      NodeList nodeList = Util.query(xml, "/samlp:Response/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", null);
      result = Util.formatCert(nodeList.item(0).getTextContent(), true).equals(Util.formatCert(certString, true));
    }

    SCRIPT_LOGGER.debug("SAMLResource - validateAssertion -> Stop");
    return result;
  }

  @ThingworxServiceDefinition(name = "parseAssertion", description = "", category = "", isAllowOverride = false, aspects = {"isAsync:false"})
  @ThingworxServiceResult(name = "result", description = "", baseType = "INFOTABLE", aspects = {"isEntityDataShape:true", "dataShape:ds_SAMLAttributes"})
  public InfoTable parseAssertion(
          @ThingworxServiceParameter(name = "xml", description = "The XML Document", baseType = "XML", aspects = {"isRequired:true"}) Document xml) throws Exception {
    SCRIPT_LOGGER.debug("SAMLResource - parseAssertion -> Start");

    InfoTable table = InfoTableInstanceFactory.createInfoTableFromDataShape("ds_SAMLAttributes");
    ValueCollection values = new ValueCollection();

    NodeList attributeStatementNodes = Util.query(xml, "/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute", null);
    for (int i = 0; i < attributeStatementNodes.getLength(); i++) {
      Element element = (Element) attributeStatementNodes.item(i);

      switch (element.getAttribute("Name")) {
        case "userid":
          values.put("userID", new StringPrimitive(element.getTextContent()));
          break;
        case "First Name":
          values.put("firstName", new StringPrimitive(element.getTextContent()));
          break;
        case "Last Name":
          values.put("lastName", new StringPrimitive(element.getTextContent()));
          break;
        case "email":
          values.put("email", new StringPrimitive(element.getTextContent()));
          break;
        case "Role":
          values.put("role", new StringPrimitive(element.getTextContent()));
          break;
      }
    }

    table.addRow(values);

    SCRIPT_LOGGER.debug("SAMLResource - parseAssertion -> Stop");
    return table;
  }
}
