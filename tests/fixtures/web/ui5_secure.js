sap.ui.define(["sap/base/security/encodeXML"], function (encodeXML) {
  "use strict";
  // A comment mentioning eval( and document.write( must not be a finding.
  function render(userInput) {
    var el = document.getElementById("out");
    el.textContent = encodeXML(userInput);
  }
  var endpoint = "https://backend.internal/odata";
  return { render: render, endpoint: endpoint };
});
