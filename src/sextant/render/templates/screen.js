// Standalone HTML: table filters, navigation search and scroll-spy. No external dependencies.
(function () {
  "use strict";
  // Filter box above every table with more than 12 rows.
  document.querySelectorAll(".page table:not(.facts)").forEach(function (table) {
    var rows = Array.prototype.slice.call(table.tBodies[0] ? table.tBodies[0].rows : []);
    var box = document.createElement("div");
    box.className = "tablebox";
    table.parentNode.insertBefore(box, table);
    box.appendChild(table);
    if (rows.length <= 12) return;
    var input = document.createElement("input");
    input.type = "search";
    input.className = "tfilter";
    input.placeholder = "Filter " + rows.length + " rows";
    input.setAttribute("aria-label", "Filter table");
    var count = document.createElement("div");
    count.className = "tcount";
    count.setAttribute("aria-live", "polite");
    box.parentNode.insertBefore(input, box);
    box.parentNode.insertBefore(count, box.nextSibling);
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase(), shown = 0;
      rows.forEach(function (r) {
        var hit = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        r.classList.toggle("hidden-by-filter", !hit);
        if (hit) shown++;
      });
      count.textContent = q ? shown + " of " + rows.length + " rows" : "";
    });
  });

  // Navigation search.
  var nav = document.querySelector(".sidenav");
  var navSearch = document.getElementById("navsearch");
  var links = Array.prototype.slice.call(nav.querySelectorAll("a[href^='#']"));
  navSearch.addEventListener("input", function () {
    var q = navSearch.value.trim().toLowerCase();
    links.forEach(function (a) {
      a.style.display = !q || a.textContent.toLowerCase().indexOf(q) !== -1 ? "" : "none";
    });
  });

  // Highlight the section in view.
  var targets = links.map(function (a) { return document.getElementById(a.getAttribute("href").slice(1)); });
  function spy() {
    var current = 0;
    targets.forEach(function (t, i) { if (t && t.getBoundingClientRect().top < 120) current = i; });
    links.forEach(function (a, i) { a.classList.toggle("active", i === current); });
  }
  document.addEventListener("scroll", spy, { passive: true });
  spy();
})();
