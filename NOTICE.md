# Notices and provenance

## Project license

The first-party project retains the GNU Affero General Public License version 3 text in [LICENSE](LICENSE). This preparation does not change that file or silently choose an `-only` versus `-or-later` grant. Copyright ownership and the precise SPDX expression must be confirmed by the rights holder before a supported distribution makes a stronger license assertion. Preserve existing author and copyright attribution; see [AUTHORS.md](AUTHORS.md) and [source provenance](docs/source-provenance.md).

This notice is an inventory and attribution index, not a legal determination for every dependency or source report.

## Included and historical material

| Material | Attribution and scope |
| --- | --- |
| Shared IOC, MITRE, public-feed packages | [Package provenance](pkg/PROVENANCE.md) records source revision, hashes, and transformations. The pinned upstream tree includes the AGPL version 3 license text; the original attribution and license are retained. |
| Synthetic evaluation corpus | Original fictional fixtures under the project license; [notice](internal/eval/testdata/NOTICE) and [provenance](internal/eval/testdata/provenance.json). |
| Previously imported TRAM corpus | Full report excerpts have been removed. Upstream Apache-2.0 [license](LICENSES/Apache-2.0.txt) and [NOTICE](internal/eval/testdata/TRAM-NOTICE.txt) are retained for historical provenance at commit `f29793d8d665f7f552898696e00065ef24a29a20`. |
| MITRE ATT&CK identifiers and lookup metadata | MITRE ATT&CK attribution and terms in [LICENSES/MITRE-ATTACK.md](LICENSES/MITRE-ATTACK.md). ATT&CK is a registered trademark of The MITRE Corporation. |
| Go module dependencies | The [binary dependency inventory](LICENSES/dependencies/manifest.json) records exact versions, module checksums, and hashes of copied upstream license/notice files for the supported Linux amd64 executable. Root notices are preserved verbatim, including bundled third-party notices. |
| Go standard library and embedded time zones | The [toolchain inventory](LICENSES/runtime/go/manifest.json) includes Go's license/patent notices, licenses of the standard-library vendored modules actually used, and Go's IANA public-domain time-zone attribution. |
| Container certificate bundle | The final scratch image copies only the pinned builder's TLS certificate bundle as external runtime data. [Certificate provenance and notices](LICENSES/runtime/certificates/README.md) identify its exact Alpine/Mozilla source and provide the MPL-2.0 license and source-availability notice. Alpine build utilities are not copied into the final image. |

`make licenses` regenerates the binary/toolchain inventories from the pinned toolchain and actual target graph. `make licenses-check` rejects drift and missing upstream license files without changing the tree. These notices are included in binary release archives and the container; their inclusion does not assign a new license to upstream material or replace release-time rights review. Test-only dependencies and developer tools are outside this executable inventory and retain their own upstream terms.

Fetching public source content does not transfer its ownership or guarantee redistribution rights. Operators are responsible for the terms applicable to collected reports, model providers, generated output, and their own feed distribution. See [releases](docs/releases.md) for the final inventory/rights gate.
