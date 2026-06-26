# S08-RW1 Review-Seed Repository Synthesis Forward Test

S08-RW1 consumed S07-RW1 review-seed artifacts and generated an unresolved repository scaffold. It did not synthesize confirmed or inferred-C implementation logic.

## New implementation

- `skills/synthesize-hypervisor-repository/scripts/generate_s08_review_seed_repository.py`

## New artifacts

- `cases/xen_arm64-778090a1/stages/S08/recovered-repo/`
- `cases/xen_arm64-778090a1/stages/S08/recovery-index.json`
- `cases/xen_arm64-778090a1/stages/S08/build-manifest.json`
- `cases/xen_arm64-778090a1/stages/S08/source-map.json`
- `cases/xen_arm64-778090a1/stages/S08/address-to-source.json`
- `cases/xen_arm64-778090a1/stages/S08/evidence-to-source.json`
- `cases/xen_arm64-778090a1/stages/S08/coverage-summary.json`
- `cases/xen_arm64-778090a1/stages/S08/recovery-evidence-index.json`
- `cases/xen_arm64-778090a1/stages/S08/recovery-decision-index.json`
- `cases/xen_arm64-778090a1/stages/S08/recovery-unknown-index.json`
- `cases/xen_arm64-778090a1/stages/S08/unresolved-index.jsonl`
- `cases/xen_arm64-778090a1/stages/S08/stage-manifest.json`
- `cases/xen_arm64-778090a1/stages/S08/artifact-validation-rw1.json`

## Result

| Item | Value |
|---|---:|
| scaffold files | 6 |
| confirmed source units | 0 |
| inferred-C units | 0 |
| asm fallback placeholders | 1 |
| explicit stub units | 2 |
| unresolved items | 3 |
| validation | `pass` |

## Gate status

- S08 status: `review_seed_repository_ready_production_blocked`
- Production gate: blocked because S07 has no confirmed lifecycle/HKIP source semantics.
- Review-seed gate: ready for S09 index-consistency audit only.

## Skill optimizations from this run

- `synthesize-hypervisor-repository` now has an explicit review-seed path.
- `generate-recovery-source-map` must avoid address-to-function claims for unresolved scaffold files.
- `index-recovery-evidence` must keep confirmed/inferred-C coverage at zero for review-seed scaffold output.
