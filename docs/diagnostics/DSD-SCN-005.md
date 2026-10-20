# DSD-SCN-005: Limit reached

Warning diagnostic: a scanner safety limit was reached: YAML depth (256), Dockerfile line length, the alias expansion budget, the HCL depth limit (256) or the Terraform node budget. The affected subtree is not scanned.

The finding limits bound the report of a hostile repository: one file reports at most 10000 findings (`finding limit reached: 10000 findings per file`) and one repository scan reports at most 100000 (`finding limit reached: 100000 findings per repository`). The first findings are kept, in the order they were found for a file and in the contract order (spec section 4) for a repository, and the limit is reported once per file or per repository: the findings that are not kept are never dropped silently.
