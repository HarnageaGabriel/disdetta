# DSD-SCN-007: Template text scanned line by line

Info diagnostic: the file is Helm template text (`templates/`, `*.tpl`, or YAML with `{{` that does not parse), scanned line by line (spec section 9.1). It is not an error: the scan stays complete. Only the static part of a reference is printed; template bodies are never shown.
