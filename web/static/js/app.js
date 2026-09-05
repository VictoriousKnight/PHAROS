/*
 * Pharos CDR Web UI
 *
 * Dependency-free browser-side behavior.
 *
 * Responsibilities:
 *   - Upload/drop-zone interaction
 *   - File selection feedback
 *   - Accessible form states
 *   - Result-page utility behavior
 *   - Safe client-side formatting
 *
 * This file deliberately does NOT:
 *   - execute uploaded documents
 *   - inspect uploaded document contents
 *   - download remote resources
 *   - execute macros/scripts
 *   - perform malware analysis
 *
 * All security-sensitive analysis remains server-side.
 */

(function () {
    "use strict";


    /* ----------------------------------------------------------------------
       Constants
       ---------------------------------------------------------------------- */

    const SELECTORS = {
        scanForm: "#scan-form",
        fileInput: "#file-input",
        dropZone: "#drop-zone",
        selectedFile: "#selected-file",
        errorBox: "#scan-error",
        scanButton: "#scan-button",
        scanButtonLabel: "#scan-button-label",
        spinner: "#scan-spinner"
    };


    /* ----------------------------------------------------------------------
       Utility functions
       ---------------------------------------------------------------------- */

    function query(selector, root) {
        return (root || document).querySelector(selector);
    }


    function queryAll(selector, root) {
        return Array.from(
            (root || document).querySelectorAll(selector)
        );
    }


    function formatBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes < 0) {
            return "unknown size";
        }

        if (bytes < 1024) {
            return bytes + " B";
        }

        if (bytes < 1024 * 1024) {
            return (bytes / 1024).toFixed(1) + " KB";
        }

        if (bytes < 1024 * 1024 * 1024) {
            return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        }

        return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
    }


    function escapeHtml(value) {
        const text = String(value);

        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    function showElement(element) {
        if (!element) {
            return;
        }

        element.hidden = false;
    }


    function hideElement(element) {
        if (!element) {
            return;
        }

        element.hidden = true;
    }


    /* ----------------------------------------------------------------------
       Scan upload UI
       ---------------------------------------------------------------------- */

    function initializeScanForm() {
        const form = query(SELECTORS.scanForm);

        if (!form) {
            return;
        }

        const input = query(SELECTORS.fileInput, form);
        const dropZone = query(SELECTORS.dropZone, form);
        const selectedFile = query(
            SELECTORS.selectedFile,
            form
        );
        const errorBox = query(
            SELECTORS.errorBox,
            form
        );
        const scanButton = query(
            SELECTORS.scanButton,
            form
        );
        const scanButtonLabel = query(
            SELECTORS.scanButtonLabel,
            form
        );
        const spinner = query(
            SELECTORS.spinner,
            form
        );

        if (!input || !dropZone) {
            return;
        }


        function showError(message) {
            if (!errorBox) {
                return;
            }

            errorBox.textContent = message;
            showElement(errorBox);
        }


        function clearError() {
            if (!errorBox) {
                return;
            }

            errorBox.textContent = "";
            hideElement(errorBox);
        }


        function displayFile(file) {
            if (!selectedFile) {
                return;
            }

            if (!file) {
                selectedFile.textContent = "No file selected";
                selectedFile.classList.remove("has-file");
                return;
            }

            const name = file.name || "Unnamed file";
            const size = formatBytes(file.size);

            selectedFile.textContent =
                name + " (" + size + ")";

            selectedFile.classList.add("has-file");
        }


        function setSubmitting(submitting) {
            if (scanButton) {
                scanButton.disabled = submitting;
                scanButton.setAttribute(
                    "aria-busy",
                    submitting ? "true" : "false"
                );
            }

            if (spinner) {
                spinner.hidden = !submitting;
            }

            if (scanButtonLabel) {
                scanButtonLabel.textContent = submitting
                    ? "Analyzing…"
                    : "Analyze Document";
            }
        }


        function selectFiles(files) {
            if (!files || !files.length) {
                displayFile(null);
                return;
            }

            const file = files[0];

            /*
             * FileList is normally read-only. Browsers that support
             * DataTransfer assignment allow the dropped FileList to be
             * transferred into the file input. If assignment is unavailable,
             * the UI still displays the file and the normal input remains
             * usable.
             */
            try {
                if (typeof DataTransfer !== "undefined") {
                    const transfer = new DataTransfer();
                    transfer.items.add(file);
                    input.files = transfer.files;
                }
            } catch (error) {
                /*
                 * Do not expose implementation details to the user.
                 * The browser can still use the normal file chooser.
                 */
            }

            displayFile(file);
            clearError();
        }


        function activateFileChooser() {
            input.click();
        }


        input.addEventListener("change", function () {
            clearError();

            if (!input.files || !input.files.length) {
                displayFile(null);
                return;
            }

            displayFile(input.files[0]);
        });


        dropZone.addEventListener("click", function (event) {
            if (event.target === input) {
                return;
            }

            activateFileChooser();
        });


        dropZone.addEventListener("keydown", function (event) {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                activateFileChooser();
            }
        });


        [
            "dragenter",
            "dragover"
        ].forEach(function (eventName) {
            dropZone.addEventListener(
                eventName,
                function (event) {
                    event.preventDefault();
                    event.stopPropagation();

                    dropZone.classList.add("drag-active");
                }
            );
        });


        [
            "dragleave",
            "drop"
        ].forEach(function (eventName) {
            dropZone.addEventListener(
                eventName,
                function (event) {
                    event.preventDefault();
                    event.stopPropagation();

                    dropZone.classList.remove("drag-active");
                }
            );
        });


        dropZone.addEventListener(
            "drop",
            function (event) {
                const files =
                    event.dataTransfer &&
                    event.dataTransfer.files;

                if (!files || !files.length) {
                    return;
                }

                selectFiles(files);
            }
        );


        form.addEventListener(
            "submit",
            function (event) {
                clearError();

                if (!input.files || !input.files.length) {
                    event.preventDefault();

                    showError(
                        "Please choose a document before starting the scan."
                    );

                    return;
                }

                const file = input.files[0];

                if (!file) {
                    event.preventDefault();

                    showError(
                        "The selected file could not be read."
                    );

                    return;
                }

                if (file.size <= 0) {
                    event.preventDefault();

                    showError(
                        "The selected file is empty."
                    );

                    return;
                }

                /*
                 * Do not attempt to determine whether a document is
                 * malicious in the browser. The server-side ingestion layer
                 * is the authoritative validator.
                 */
                setSubmitting(true);
            }
        );


        displayFile(
            input.files && input.files.length
                ? input.files[0]
                : null
        );
    }


    /* ----------------------------------------------------------------------
       Copy-to-clipboard functionality
       ---------------------------------------------------------------------- */

    function initializeCopyButtons() {
        const buttons = queryAll(
            "[data-copy-target]"
        );

        if (!buttons.length) {
            return;
        }

        buttons.forEach(function (button) {
            button.addEventListener(
                "click",
                async function () {
                    const selector =
                        button.getAttribute("data-copy-target");

                    if (!selector) {
                        return;
                    }

                    const target = query(selector);

                    if (!target) {
                        return;
                    }

                    const text =
                        target.textContent || "";

                    if (!text) {
                        return;
                    }

                    try {
                        if (
                            navigator.clipboard &&
                            typeof navigator.clipboard.writeText ===
                            "function"
                        ) {
                            await navigator.clipboard.writeText(text);
                        } else {
                            copyUsingFallback(text);
                        }

                        indicateCopySuccess(button);
                    } catch (error) {
                        indicateCopyFailure(button);
                    }
                }
            );
        });
    }


    function copyUsingFallback(text) {
        const textarea =
            document.createElement("textarea");

        textarea.value = text;

        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.left = "-9999px";
        textarea.style.top = "0";

        document.body.appendChild(textarea);

        textarea.focus();
        textarea.select();

        const successful =
            document.execCommand("copy");

        document.body.removeChild(textarea);

        if (!successful) {
            throw new Error("Clipboard copy failed.");
        }
    }


    function indicateCopySuccess(button) {
        const original =
            button.getAttribute("data-copy-label") ||
            button.textContent;

        button.setAttribute(
            "data-copy-label",
            original
        );

        button.textContent = "Copied";

        window.setTimeout(function () {
            button.textContent = original;
        }, 1500);
    }


    function indicateCopyFailure(button) {
        const original =
            button.getAttribute("data-copy-label") ||
            button.textContent;

        button.textContent = "Copy failed";

        window.setTimeout(function () {
            button.textContent = original;
        }, 1500);
    }


    /* ----------------------------------------------------------------------
       External-link hardening
       ---------------------------------------------------------------------- */

    function initializeExternalLinks() {
        const links = queryAll(
            "a[target='_blank']"
        );

        links.forEach(function (link) {
            const existing =
                link.getAttribute("rel") || "";

            const values = new Set(
                existing
                    .split(/\s+/)
                    .filter(Boolean)
            );

            values.add("noopener");
            values.add("noreferrer");

            link.setAttribute(
                "rel",
                Array.from(values).join(" ")
            );
        });
    }


    /* ----------------------------------------------------------------------
       Result-page enhancements
       ---------------------------------------------------------------------- */

    function initializeResultPage() {
        const resultPage =
            query("[data-result-page]");

        if (!resultPage) {
            return;
        }

        /*
         * Keep very long hash values readable on small screens without
         * modifying the underlying value.
         */
        queryAll(".hash-value", resultPage).forEach(
            function (element) {
                element.setAttribute(
                    "title",
                    element.textContent.trim()
                );
            }
        );
    }


    /* ----------------------------------------------------------------------
       Accessibility helpers
       ---------------------------------------------------------------------- */

    function initializeAccessibility() {
        queryAll("[hidden]").forEach(function (element) {
            /*
             * Do not alter the browser's hidden state. This loop only exists
             * as a single initialization point for future accessibility
             * behavior.
             */
            if (!element.hasAttribute("aria-hidden")) {
                return;
            }
        });
    }


    /* ----------------------------------------------------------------------
       Initialization
       ---------------------------------------------------------------------- */

    function initialize() {
        initializeScanForm();
        initializeCopyButtons();
        initializeExternalLinks();
        initializeResultPage();
        initializeAccessibility();
    }


    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            initialize,
            { once: true }
        );
    } else {
        initialize();
    }


    /* ----------------------------------------------------------------------
       Public browser API
       ----------------------------------------------------------------------
       These functions are intentionally exposed only for pages that need
       lightweight UI integration. They do not expose scanner internals.
       ---------------------------------------------------------------------- */

    window.PharosCDR = Object.freeze({
        formatBytes: formatBytes,
        escapeHtml: escapeHtml
    });

})();