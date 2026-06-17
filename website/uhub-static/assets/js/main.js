/* uhub.org — static site behaviour */
(function () {
	"use strict";

	// Mobile navigation toggle
	var toggle = document.querySelector(".nav-toggle");
	var links = document.querySelector(".nav-links");
	if (toggle && links) {
		toggle.addEventListener("click", function () {
			links.classList.toggle("open");
		});
	}

	// Configuration reference: live filter + expand/collapse all
	var search = document.getElementById("config-search");
	if (search) {
		var directives = Array.prototype.slice.call(
			document.querySelectorAll(".directive")
		);
		var groups = Array.prototype.slice.call(
			document.querySelectorAll(".config-group")
		);
		var noResults = document.querySelector(".no-results");

		search.addEventListener("input", function () {
			var q = search.value.trim().toLowerCase();
			var anyVisible = false;

			directives.forEach(function (d) {
				var hay = (d.dataset.name + " " + d.dataset.desc).toLowerCase();
				var match = q === "" || hay.indexOf(q) !== -1;
				d.style.display = match ? "" : "none";
				if (match) anyVisible = true;
				if (q !== "" && match) {
					d.open = true;
				} else if (q === "") {
					d.open = false;
				}
			});

			// Hide group headings that have no visible directives
			groups.forEach(function (g) {
				var visible = g.querySelectorAll(
					'.directive:not([style*="display: none"])'
				).length;
				g.style.display = visible > 0 ? "" : "none";
			});

			if (noResults) {
				noResults.style.display = anyVisible ? "none" : "block";
			}
		});
	}

	function setAll(open) {
		Array.prototype.forEach.call(
			document.querySelectorAll(".directive"),
			function (d) {
				if (d.style.display !== "none") d.open = open;
			}
		);
	}
	var expandBtn = document.getElementById("expand-all");
	var collapseBtn = document.getElementById("collapse-all");
	if (expandBtn) expandBtn.addEventListener("click", function () { setAll(true); });
	if (collapseBtn) collapseBtn.addEventListener("click", function () { setAll(false); });
})();
