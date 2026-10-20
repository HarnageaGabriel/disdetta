# DSD-SCN-005: Limit reached

Warning diagnostic: a scanner safety limit was reached: YAML depth (256), Dockerfile line length, the alias expansion budget, the HCL depth limit (256), the Terraform node budget (100000), the Terraform heredoc body limit (20000 lines) or the Terraform file limit (200000 lines). The affected subtree is not scanned.

A Dockerfile logical instruction is limited to 10000 continuation lines: a longer chain is not scanned, is reported once as this warning at the start line of the instruction, and the instructions after the chain are still scanned.
