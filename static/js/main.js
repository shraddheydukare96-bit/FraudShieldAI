/* FraudShield AI - shared front-end behavior */
(function () {
  "use strict";

  // Auto-dismiss flash alerts after a few seconds for a cleaner UX.
  document.addEventListener("DOMContentLoaded", function () {
    var alerts = document.querySelectorAll(".alert-dismissible");
    alerts.forEach(function (alertEl) {
      setTimeout(function () {
        var bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
        bsAlert.close();
      }, 6000);
    });

    // Client-side password-match hint for the signup form (progressive enhancement).
    var pw = document.getElementById("id_password1");
    var pw2 = document.getElementById("id_password2");
    if (pw && pw2) {
      pw2.addEventListener("input", function () {
        if (pw2.value && pw.value !== pw2.value) {
          pw2.classList.add("is-invalid");
        } else {
          pw2.classList.remove("is-invalid");
        }
      });
    }
  });
})();
