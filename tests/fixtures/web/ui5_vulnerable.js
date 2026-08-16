sap.ui.define([], function () {
  "use strict";
  var apiKey = "abcd1234efgh5678";
  function render(userInput) {
    var el = document.getElementById("out");
    el.innerHTML = "<b>" + userInput + "</b>";
    document.write("<i>" + userInput + "</i>");
    eval(userInput);
  }
  var endpoint = "http://backend.internal/odata";
  return { render: render, endpoint: endpoint };
});
