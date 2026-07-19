# Release decision

## NOT READY

The repository is not ready for an enterprise demonstration from this validation environment. Core Python tests and the frontend build pass, but Docker deployment cannot be executed, framework runtime commands cannot start, and the required end-to-end vulnerable/hardened comparison with real specialized model invocations was not reproducible.

Before reconsideration, run the commands in `FINAL_VALIDATION.md` on an Ubuntu host with Docker access and the project environment installed. The release may only be reconsidered when Docker services are healthy, all framework stages execute, attacker/judge invocation evidence exists, handoffs are causally consumed, native confirmation is present, and hardened performance improves measurably.
